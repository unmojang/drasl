package main

import (
	"errors"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
)

type sessionJoinRequest struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

// /session/minecraft/join
// https://wiki.vg/Protocol_Encryption#Client
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

		user := client.User

		user.ServerID = MakeNullString(&req.ServerID)
		result := app.DB.Save(&user)
		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	}
}

func fullProfile(app *App, user *User, uuid string, sign bool) (SessionProfileResponse, error) {
	id, err := UUIDToID(uuid)
	if err != nil {
		return SessionProfileResponse{}, err
	}

	texturesProperty, err := app.GetSkinTexturesProperty(user, sign)
	if err != nil {
		return SessionProfileResponse{}, err
	}

	return SessionProfileResponse{
		ID:         id,
		Name:       user.PlayerName,
		Properties: []SessionProfileProperty{texturesProperty},
	}, nil
}

// /session/minecraft/hasJoined
// https://c4k3.github.io/wiki.vg/Protocol_Encryption.html#Server
func SessionHasJoined(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.QueryParam("username")
		serverID := c.QueryParam("serverId")

		var user User
		result := app.DB.First(&user, "player_name = ?", playerName)
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			if app.Config.TransientUsers.Allow && app.TransientUsernameRegex.MatchString(playerName) {
				var err error
				user, err = MakeTransientUser(app, playerName)
				if err != nil {
					return err
				}
			} else {
				return c.NoContent(http.StatusForbidden)
			}
		}

		if result.Error != nil || !user.ServerID.Valid || serverID != user.ServerID.String {
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
					return c.Stream(http.StatusOK, res.Header.Get("Content-Type"), res.Body)
				}
			}

			return c.NoContent(http.StatusForbidden)
		}

		profile, err := fullProfile(app, &user, user.UUID, true)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	}
}

// /session/minecraft/profile/:id
// https://wiki.vg/Mojang_API#UUID_to_Profile_and_Skin.2FCape
func SessionProfile(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		id := c.Param("id")
		uuid, err := IDToUUID(id)
		if err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				ErrorMessage: Ptr("Not a valid UUID: " + c.Param("id")),
			})
		}

		findUser := func() (*User, error) {
			var user User
			result := app.DB.First(&user, "uuid = ?", uuid)
			if result.Error == nil {
				return &user, nil
			}
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return nil, err
			}

			// Could be an offline UUID
			if app.Config.OfflineSkins {
				result = app.DB.First(&user, "offline_uuid = ?", uuid)
				if result.Error == nil {
					return &user, nil
				}
				if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
					return nil, err
				}
			}

			return nil, nil
		}

		user, err := findUser()
		if err != nil {
			return err
		}

		if user == nil {
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
		profile, err := fullProfile(app, user, uuid, sign)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	}
}

// /blockedservers
// https://wiki.vg/Mojang_API#Blocked_Servers
func SessionBlockedServers(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	}
}
