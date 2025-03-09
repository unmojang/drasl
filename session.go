package main

import (
	"errors"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type sessionJoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

// /session/minecraft/join
// https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_Encryption#Client
func SessionJoin(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(sessionJoinRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyDeny)
		if client == nil {
			return c.JSONBlob(http.StatusForbidden, invalidAccessTokenBlob)
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
		client := app.GetClient(accessToken, StalePolicyDeny)
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
		for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
			if fallbackAPIServer.DenyUnknownUsers && result.Error != nil {
				// If DenyUnknownUsers is enabled and the player name is
				// not known, don't query the fallback server.
				continue
			}
			base, err := url.Parse(fallbackAPIServer.SessionURL)
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
			return (*c).String(http.StatusMethodNotAllowed, "NO")
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

		var uuid_ string
		uuid_, err := IDToUUID(id)
		if err != nil {
			_, err = uuid.Parse(id)
			if err != nil {
				return c.JSON(http.StatusBadRequest, ErrorResponse{
					ErrorMessage: Ptr("Not a valid UUID: " + c.Param("id")),
				})
			}
			uuid_ = id
		}

		findPlayer := func() (*Player, *User, error) {
			var player Player
			result := app.DB.Preload("User").First(&player, "uuid = ?", uuid_)
			if result.Error == nil {
				return &player, &player.User, nil
			}
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return nil, nil, err
			}

			// Could be an offline UUID
			if app.Config.OfflineSkins {
				result = app.DB.Preload("User").First(&player, "offline_uuid = ?", uuid_)
				if result.Error == nil {
					return &player, &player.User, nil
				}
				if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
					return nil, nil, err
				}
			}

			return nil, nil, nil
		}

		player, user, err := findPlayer()
		if err != nil {
			return err
		}

		if player == nil {
			for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
				reqURL, err := url.JoinPath(fallbackAPIServer.SessionURL, "session/minecraft/profile", id)
				if err != nil {
					log.Println(err)
					continue
				}
				res, err := app.CachedGet(reqURL+"?unsigned=false", fallbackAPIServer.CacheTTLSeconds)
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
