package main

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
)

// /session/minecraft/join
func SessionJoin(app *App) func(c echo.Context) error {
	type sessionJoinRequest struct {
		AccessToken     string `json:"accessToken"`
		SelectedProfile string `json:"selectedProfile"`
		ServerID        string `json:"serverId"`
	}

	return func(c echo.Context) error {
		req := new(sessionJoinRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var tokenPair TokenPair
		result := app.DB.Preload("User").First(&tokenPair, "access_token = ?", req.AccessToken)
		if result.Error != nil {
			// TODO check not found
			return c.NoContent(http.StatusForbidden)
		}
		user := tokenPair.User

		if req.AccessToken != tokenPair.AccessToken {
			return c.JSON(http.StatusForbidden, ErrorResponse{
				Error:        "ForbiddenOperationException",
				ErrorMessage: "Invalid access token.",
			})
		}
		if !tokenPair.Valid {
			return c.JSON(http.StatusForbidden, ErrorResponse{
				Error:        "ForbiddenOperationException",
				ErrorMessage: "Access token has expired.",
			})
		}

		user.ServerID = MakeNullString(&req.ServerID)
		result = app.DB.Save(&user)
		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	}
}

func fullProfile(app *App, user *User, sign bool) (ProfileResponse, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return ProfileResponse{}, err
	}

	texturesProperty, err := GetSkinTexturesProperty(app, user, sign)
	if err != nil {
		return ProfileResponse{}, err
	}

	return ProfileResponse{
		ID:         id,
		Name:       user.PlayerName,
		Properties: []ProfileProperty{texturesProperty},
	}, nil
}

// /session/minecraft/hasJoined
func SessionHasJoined(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.QueryParam("username")
		serverID := c.QueryParam("serverId")

		var user User
		result := app.DB.First(&user, "player_name = ?", playerName)
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			if app.Config.AnonymousLogin.Allow && app.AnonymousLoginUsernameRegex.MatchString(playerName) {
				var err error
				user, err = MakeAnonymousUser(app, playerName)
				if err != nil {
					return err
				}
			} else {
				return c.NoContent(http.StatusForbidden)
			}
		}

		if result.Error != nil || !user.ServerID.Valid || serverID != user.ServerID.String {
			for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
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

				res, err := http.Get(base.String())
				if err != nil {
					log.Println(err)
					continue
				}
				defer res.Body.Close()

				if res.StatusCode == http.StatusOK {
					return c.Stream(http.StatusOK, res.Header.Get("Content-Type"), res.Body)
				}
			}

			return c.NoContent(http.StatusForbidden)
		}

		profile, err := fullProfile(app, &user, true)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	}
}

// /session/minecraft/profile/:id
func SessionProfile(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		uuid, err := IDToUUID(c.Param("id"))
		if err != nil {
			return err
		}

		var user User
		result := app.DB.First(&user, "uuid = ?", uuid)
		if result.Error != nil {
			return err
		}

		profile, err := fullProfile(app, &user, true)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	}
}
