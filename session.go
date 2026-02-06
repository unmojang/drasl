package main

import (
	"container/list"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sessionJoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

type ServerKey struct {
	IP   string
	Port int
}

type heartbeatSaltEntry struct {
	Salt      string
	Timestamp time.Time
	Elem      *list.Element
}

var (
	heartbeatSaltMap      = make(map[ServerKey]heartbeatSaltEntry)
	heartbeatSaltMapMutex sync.RWMutex
	heartbeatLruList      = list.New()
	heartbeatLruMutex     sync.Mutex
	heartbeatLruTTL       = 5 * time.Minute // Server should send one every 45 seconds
)

// /session/minecraft/join
// https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_Encryption#Client
func SessionJoin(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(sessionJoinRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client, err := app.GetClient(req.AccessToken, StalePolicyDeny)
		var userError *UserError
		if err != nil && !errors.As(err, &userError) {
			return err
		}
		if client == nil {
			return &YggdrasilError{Code: http.StatusForbidden, Error_: mo.Some("ForbiddenOperationException")}
		}

		player := client.Player

		player.ServerID = MakeNullString(&req.ServerID)
		result := app.DB.Save(&player)
		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	}
}

// /game/joinserver.jsp
func SessionJoinServer(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.QueryParam("user")
		sessionID := c.QueryParam("sessionId")
		serverID := c.QueryParam("serverId")

		// If any parameters are missing, return NO
		if playerName == "" || sessionID == "" || serverID == "" {
			return c.String(http.StatusOK, "Bad login")

		}

		// Parse sessionId. It has the form:
		// token:<accessToken>:<player UUID>
		split := strings.Split(sessionID, ":")
		if len(split) != 3 || split[0] != "token" {
			return c.String(http.StatusOK, "Bad login")
		}
		accessToken := split[1]
		id := split[2]

		// Is the accessToken valid?
		client, err := app.GetClient(accessToken, StalePolicyDeny)
		var userError *UserError
		if err != nil && !errors.As(err, &userError) {
			return err
		}

		if client == nil {
			return c.String(http.StatusOK, "Bad login")
		}

		// If the player name corresponding to the access token doesn't match
		// the `user` param from the request, return NO
		player := client.Player
		if player.Name != playerName {
			return c.String(http.StatusOK, "Bad login")
		}
		// If the player's UUID doesn't match the UUID in the sessionId, return
		// NO
		playerID, err := UUIDToID(player.UUID)
		if err != nil {
			return err
		}
		if playerID != id {
			return c.String(http.StatusOK, "Bad login")
		}

		player.ServerID = MakeNullString(&serverID)
		result := app.DB.Save(&player)
		if result.Error != nil {
			return result.Error
		}

		return c.String(http.StatusOK, "OK")
	}
}

func fullProfile(app *App, user *User, player *Player, uuid string, sign bool, fromAuthlibInjector bool) (SessionProfileResponse, error) {
	id, err := UUIDToID(uuid)
	if err != nil {
		return SessionProfileResponse{}, err
	}

	texturesProperty, err := app.GetSkinTexturesProperty(player, sign)
	if err != nil {
		return SessionProfileResponse{}, err
	}

	properties := []SessionProfileProperty{texturesProperty}

	if fromAuthlibInjector {
		var uploadableTextures []string
		if app.Config.AllowSkins || user.IsAdmin {
			uploadableTextures = append(uploadableTextures, "skin")
		}
		if app.Config.AllowCapes || user.IsAdmin {
			uploadableTextures = append(uploadableTextures, "cape")
		}
		properties = append(properties, SessionProfileProperty{
			Name:  "uploadableTextures",
			Value: strings.Join(uploadableTextures, ","),
		})
	}

	return SessionProfileResponse{
		ID:         id,
		Name:       player.Name,
		Properties: properties,
	}, nil
}

func (app *App) hasJoined(c *echo.Context, playerName string, serverID string, legacy bool) error {
	var player Player
	result := app.DB.Preload("User").First(&player, "name = ?", playerName)
	user := player.User
	// If the error isn't "not found", throw.
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	if result.Error != nil || !player.ServerID.Valid || serverID != player.ServerID.String {
		for _, fallbackAPIServer := range app.FallbackAPIServers {
			if !fallbackAPIServer.Config.EnableAuthentication {
				continue
			}
			if fallbackAPIServer.Config.DenyUnknownUsers && result.Error != nil {
				// If DenyUnknownUsers is enabled and the player name is
				// not known, don't query the fallback server.
				continue
			}
			base, err := url.Parse(fallbackAPIServer.Config.SessionURL)
			if err != nil {
				log.Println(err)
				continue
			}

			base.Path += "/session/minecraft/hasJoined"
			params := url.Values{}
			params.Add("username", playerName)
			params.Add("serverId", serverID)
			base.RawQuery = params.Encode()

			res, err := MakeHTTPClient().Get(base.String())
			if err != nil {
				log.Printf("Received invalid response from fallback API server at %s\n", base.String())
				continue
			}
			defer res.Body.Close()

			if res.StatusCode == http.StatusOK {
				if legacy {
					return (*c).String(http.StatusOK, "YES")
				} else {
					return (*c).Stream(http.StatusOK, res.Header.Get("Content-Type"), res.Body)
				}
			}
		}

		if legacy {
			return (*c).String(http.StatusOK, "NO")
		} else {
			return (*c).NoContent(http.StatusForbidden)
		}
	}

	if legacy {
		return (*c).String(http.StatusOK, "YES")
	}

	profile, err := fullProfile(app, &user, &player, player.UUID, true, false)
	if err != nil {
		return err
	}

	return (*c).JSON(http.StatusOK, profile)
}

// /session/minecraft/hasJoined
// https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_Encryption#Server
func SessionHasJoined(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.QueryParam("username")
		serverID := c.QueryParam("serverId")
		return app.hasJoined(&c, playerName, serverID, false)
	}
}

// /game/checkserver.jsp
func SessionCheckServer(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.QueryParam("user")
		serverID := c.QueryParam("serverId")
		return app.hasJoined(&c, playerName, serverID, true)
	}
}

// /session/minecraft/profile/:id
// https://minecraft.wiki/w/Mojang_API#Query_player's_skin_and_cape
func SessionProfile(app *App, fromAuthlibInjector bool) func(c echo.Context) error {
	return func(c echo.Context) error {
		id := c.Param("id")
		uuid_, err := ParseUUID(id)
		if err != nil {
			return &YggdrasilError{
				Code:         http.StatusBadRequest,
				ErrorMessage: mo.Some(fmt.Sprintf("Not a valid UUID: %s", id)),
			}
		}

		player, user, err := app.FindPlayerByUUIDOrOfflineUUID(uuid_)
		if err != nil {
			return err
		}

		if player == nil {
			for _, fallbackAPIServer := range app.FallbackAPIServers {
				reqURL := fallbackAPIServer.Config.SessionURL + "/session/minecraft/profile/" + url.PathEscape(uuid_)
				res, err := app.CachedGet(reqURL+"?unsigned=false", fallbackAPIServer.Config.CacheTTLSeconds)
				if err != nil {
					log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
					continue
				}

				if res.StatusCode == http.StatusOK {
					return c.Blob(http.StatusOK, "application/json", res.BodyBytes)
				}
			}
			return c.NoContent(http.StatusNoContent)
		}

		sign := c.QueryParam("unsigned") == "false"
		profile, err := fullProfile(app, user, player, uuid_, sign, fromAuthlibInjector)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	}
}

// /blockedservers
// https://minecraft.wiki/w/Mojang_API#Query_blocked_server_list
func SessionBlockedServers(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	}
}

func (app *App) heartbeat(c *echo.Context, ip string, port int, salt string) error {
	key := ServerKey{IP: ip, Port: port}
	now := time.Now()

	heartbeatSaltMapMutex.Lock()
	entry, exists := heartbeatSaltMap[key]
	if exists {
		// Update value by overwriting the map entry
		entry.Salt = salt
		entry.Timestamp = now
		heartbeatSaltMap[key] = entry
	} else {
		// New entry
		entry = heartbeatSaltEntry{
			Salt:      salt,
			Timestamp: now,
		}
		heartbeatSaltMap[key] = entry
	}

	heartbeatSaltMapMutex.Unlock()

	// Handle heartbeat LRU
	heartbeatLruMutex.Lock()
	if exists {
		heartbeatLruList.MoveToFront(entry.Elem)
	} else {
		entry.Elem = heartbeatLruList.PushFront(key)
		// Save back updated element
		heartbeatSaltMapMutex.Lock()
		heartbeatSaltMap[key] = entry
		heartbeatSaltMapMutex.Unlock()
	}

	// Enforce max size for list (256)
	for heartbeatLruList.Len() > 256 {
		back := heartbeatLruList.Back()
		if back == nil {
			break
		}
		oldKey := back.Value.(ServerKey)

		heartbeatSaltMapMutex.Lock()
		delete(heartbeatSaltMap, oldKey)
		heartbeatSaltMapMutex.Unlock()

		heartbeatLruList.Remove(back)
	}

	heartbeatLruMutex.Unlock()

	return (*c).String(http.StatusOK, "http://www.minecraft.net/classic/play/foobar")
}

// /heartbeat.jsp
// https://minecraft.wiki/w/Classic_server_protocol
// https://www.grahamedgecombe.com/talks/minecraft.pdf
func SessionHeartbeat(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		ip := c.RealIP()
		if app.isLocalIP(ip) {
			publicIP, err := app.getPublicIP()
			if err == nil {
				ip = publicIP
			}
		}

		// Require port
		portStr := c.FormValue("port")
		if portStr == "" {
			portStr = c.QueryParam("port")
		}
		if portStr == "" {
			return c.String(http.StatusBadRequest, "missing required query parameter: port")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid port value")
		}

		// Require salt
		salt := c.FormValue("salt")
		if salt == "" {
			salt = c.QueryParam("salt")
		}
		if salt == "" {
			return c.String(http.StatusBadRequest, "missing required query parameter: salt")
		}

		return app.heartbeat(&c, ip, port, salt)
	}
}

func (app *App) getMpPass(c *echo.Context, playerName string, ip string, port int) error {
	key := ServerKey{IP: ip, Port: port}

	heartbeatSaltMapMutex.RLock()
	entry, ok := heartbeatSaltMap[key]
	heartbeatSaltMapMutex.RUnlock()

	if !ok {
		return (*c).NoContent(http.StatusNotFound)
	}

	hash := md5.Sum([]byte(entry.Salt + playerName))
	return (*c).String(http.StatusOK, hex.EncodeToString(hash[:]))
}

func SessionGetMpPass(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User, _ *Player) error {
		// Get IP from query param
		ip := c.QueryParam("ip")
		if ip == "" {
			return c.String(http.StatusBadRequest, "missing required query parameter: ip")
		}

		// Get port (optional, default 25565)
		port := 25565
		portStr := c.QueryParam("port")
		if portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return c.String(http.StatusBadRequest, "invalid port value")
			}
			port = p
		}

		// Get player name
		playerName := c.QueryParam("player")
		if playerName == "" {
			return c.String(http.StatusBadRequest, "missing required query parameter: player")
		}

		// Check if user owns the requested player
		found := false
		for _, currentPlayer := range user.Players {
			if currentPlayer.Name == playerName {
				found = true
				break
			}
		}

		if !found {
			return c.NoContent(http.StatusUnauthorized)
		}

		return app.getMpPass(&c, playerName, ip, port)
	})
}
