package main

import (
	"container/list"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/samber/mo"
	"gorm.io/gorm"
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
	heartbeatLruTTL = 5 * time.Minute // Server should send one every 45 seconds
)

// Perform request validation and authentication for SessionJoin
func (app *App) BindSessionJoin() func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := new(sessionJoinRequest)
			if err := c.Bind(req); err != nil {
				return err
			}

			client, err := app.GetClient(req.AccessToken, mo.None[string](), StalePolicyDeny, true)
			if err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					return &YggdrasilError{Code: http.StatusForbidden, Error_: mo.Some("ForbiddenOperationException")}
				} else {
					return err
				}
			}

			maybeUser := mo.Some(client.User)
			maybePlayer := mo.Some(*client.Player)
			c.Set(CONTEXT_KEY_REQ, req)
			c.Set(CONTEXT_KEY_CLIENT, client)
			c.Set(CONTEXT_KEY_MAYBE_USER, maybeUser)
			c.Set(CONTEXT_KEY_USER, maybeUser.ToPointer())
			c.Set(CONTEXT_KEY_MAYBE_PLAYER, maybePlayer)
			c.Set(CONTEXT_KEY_PLAYER, maybePlayer.ToPointer())
			return next(c)
		}
	}
}

// /session/minecraft/join
// https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_Encryption#Client
func SessionJoin(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		req := c.Get(CONTEXT_KEY_REQ).(*sessionJoinRequest)
		player := c.Get(CONTEXT_KEY_PLAYER).(*Player)
		user := c.Get(CONTEXT_KEY_USER).(*User)

		ban, forcedNameChange, err := app.CanUseMultiplayer(user, player)
		if err != nil {
			return err
		}
		if ban != nil {
			return &YggdrasilError{
				Code:         http.StatusForbidden,
				Error_:       mo.Some("DraslAccountBanned"),
				ErrorMessage: mo.Some(BanJoinMessage(ban)),
			}
		}
		if forcedNameChange {
			return &YggdrasilError{
				Code:         http.StatusForbidden,
				Error_:       mo.Some("DraslProfileActionRequired"),
				ErrorMessage: mo.Some("You must change your player name before joining an online server."),
			}
		}

		player.ServerID = MakeNullString(&req.ServerID)
		result := app.DB.Save(&player)
		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
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
	profileActions := app.ProfileActions(player)

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
		ID:             id,
		Name:           player.Name,
		Properties:     properties,
		ProfileActions: profileActions,
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

	// A known local player must never fall through to a fallback server when
	// local moderation denies multiplayer access.
	if result.Error == nil {
		ban, forcedNameChange, err := app.CanUseMultiplayer(&user, &player)
		if err != nil {
			return err
		}
		if ban != nil || forcedNameChange {
			if legacy {
				return (*c).String(http.StatusOK, "NO")
			}
			return (*c).NoContent(http.StatusForbidden)
		}
	}

	if result.Error != nil || !player.ServerID.Valid || serverID != player.ServerID.String {
		for _, nickname := range app.FallbackAPIServerNicknames {
			fallbackAPIServer := app.FallbackAPIServers[nickname]
			if !fallbackAPIServer.Config.EnableAuthentication {
				continue
			}
			if fallbackAPIServer.Config.DenyUnknownUsers && result.Error != nil {
				// If DenyUnknownUsers is enabled and the player name is
				// not known, don't query the fallback server.
				continue
			}
			hasJoinedURL, err := url.Parse(fallbackAPIServer.SessionVerifyURL)
			if err != nil {
				log.Println(err)
				continue
			}

			params := url.Values{}
			params.Add("username", playerName)
			params.Add("serverId", serverID)
			hasJoinedURL.RawQuery = params.Encode()

			res, err := MakeHTTPClient().Get(hasJoinedURL.String())
			if err != nil {
				log.Printf("Received invalid response from fallback API server at %s\n", hasJoinedURL.String())
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
func SessionHasJoined(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		playerName := c.QueryParam("username")
		serverID := c.QueryParam("serverId")
		return app.hasJoined(c, playerName, serverID, false)
	}
}

// /game/joinserver.jsp
func SessionLegacyJoin(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		playerName := c.QueryParam("user")
		accessToken := c.QueryParam("sessionId")
		serverID := c.QueryParam("serverId")
		if playerName == "" || accessToken == "" || serverID == "" {
			return c.String(http.StatusOK, "Bad login")
		}

		client, err := app.GetClient(accessToken, mo.None[string](), StalePolicyDeny, true)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return c.String(http.StatusOK, "Bad login")
			}
			return err
		}
		if !strings.EqualFold(client.Player.Name, playerName) {
			return c.String(http.StatusOK, "Bad login")
		}

		ban, forcedNameChange, err := app.CanUseMultiplayer(&client.User, client.Player)
		if err != nil {
			return err
		}
		if ban != nil || forcedNameChange {
			return c.String(http.StatusOK, "Bad login")
		}

		client.Player.ServerID = MakeNullString(&serverID)
		if err := app.DB.Save(client.Player).Error; err != nil {
			return err
		}
		return c.String(http.StatusOK, "OK")
	}
}

// /game/checkserver.jsp
func SessionLegacyCheck(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		return app.hasJoined(c, c.QueryParam("user"), c.QueryParam("serverId"), true)
	}
}

// /session/minecraft/profile/:id
// https://minecraft.wiki/w/Mojang_API#Query_player's_skin_and_cape
func SessionProfile(app *App, fromAuthlibInjector bool) func(c *echo.Context) error {
	return func(c *echo.Context) error {
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
			for _, nickname := range app.FallbackAPIServerNicknames {
				fallbackAPIServer := app.FallbackAPIServers[nickname]
				reqURL := fallbackAPIServer.SessionGetProfileByIDURL + "/" + url.PathEscape(uuid_)
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
func SessionBlockedServers(app *App) func(c *echo.Context) error {
	hashes := make([]string, len(app.Config.BlockedServers))
	for i, server := range app.Config.BlockedServers {
		sum := sha1.Sum([]byte(server))
		hashes[i] = hex.EncodeToString(sum[:])
	}
	response := strings.Join(hashes, "\n")
	return func(c *echo.Context) error {
		if response == "" {
			return c.NoContent(http.StatusOK)
		}
		return c.String(http.StatusOK, response)
	}
}

func (app *App) heartbeat(c *echo.Context, ip string, port int, salt string) error {
	key := ServerKey{IP: ip, Port: port}
	now := time.Now()

	app.HeartbeatMutex.Lock()
	defer app.HeartbeatMutex.Unlock()

	entry, exists := app.HeartbeatSaltMap[key]
	if exists {
		// Update value by overwriting the map entry
		entry.Salt = salt
		entry.Timestamp = now
		app.HeartbeatSaltMap[key] = entry
	} else {
		// New entry
		entry = heartbeatSaltEntry{
			Salt:      salt,
			Timestamp: now,
		}
		app.HeartbeatSaltMap[key] = entry
	}

	// Handle heartbeat LRU
	if exists {
		app.HeartbeatLruList.MoveToFront(entry.Elem)
	} else {
		entry.Elem = app.HeartbeatLruList.PushFront(key)
		app.HeartbeatSaltMap[key] = entry
	}

	return (*c).String(http.StatusOK, fmt.Sprintf("%s:%d", ip, port))
}

// /heartbeat.jsp
// https://minecraft.wiki/w/Classic_server_protocol
// https://www.grahamedgecombe.com/talks/minecraft.pdf
func SessionHeartbeat(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		ip := c.RealIP()
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return c.String(http.StatusInternalServerError, "failed to parse ip")
		}

		// Prefer ClassicPublicIP config over request IP on private/loopback address ranges
		if (parsed.IsLoopback() || parsed.IsPrivate()) && app.Config.ClassicPublicIP != "" {
			ip = app.Config.ClassicPublicIP
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
		if err != nil || port <= 0 || port > 65535 {
			return c.String(http.StatusBadRequest, "invalid port value")
		}

		// Require salt
		salt := c.FormValue("salt")
		if salt == "" {
			salt = c.QueryParam("salt")
		}
		if salt == "" {
			salt = "missingno" // no salt here! are we speaking with c0.0.15a-c0.0.16a?
		}

		return app.heartbeat(c, ip, port, salt)
	}
}

func (app *App) getMpPass(c *echo.Context, playerName string, ip string, port int) error {
	key := ServerKey{IP: ip, Port: port}

	app.HeartbeatMutex.RLock()
	entry, ok := app.HeartbeatSaltMap[key]
	app.HeartbeatMutex.RUnlock()

	if !ok {
		return (*c).NoContent(http.StatusNotFound)
	}

	hash := md5.Sum([]byte(entry.Salt + playerName))
	return (*c).String(http.StatusOK, hex.EncodeToString(hash[:]))
}

// Historically, Minecraft Classic was played in the browser, and the server's page on minecraft.net
// populated the `mppass` field used to validate usernames. This endpoint provides the player's
// `mppass` for the requested IP and port so that Classic authentication may function as intended.
func SessionGetMpPass(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		player := c.Get(CONTEXT_KEY_PLAYER).(*Player)
		user := c.Get(CONTEXT_KEY_USER).(*User)

		ban, forcedNameChange, err := app.CanUseMultiplayer(user, player)
		if err != nil {
			return err
		}
		if ban != nil || forcedNameChange {
			return c.NoContent(http.StatusForbidden)
		}

		ip := c.QueryParam("ip")
		if ip == "" {
			return c.String(http.StatusBadRequest, "missing required query parameter: ip")
		}

		port := 25565
		portStr := c.QueryParam("port")
		if portStr != "" {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return c.String(http.StatusBadRequest, "invalid port value")
			}
			port = p
		}

		return app.getMpPass(c, player.Name, ip, port)
	}
}
