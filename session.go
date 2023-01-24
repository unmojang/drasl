package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
	"time"
	"fmt"
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

type profileProperty struct {
	Name      string  `json:"name"`
	Value     string  `json:"value"`
	Signature *string `json:"signature,omitempty"`
}

type profileResponse struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties []profileProperty `json:"properties"`
}

type textureMetadata struct {
	Model string `json:"string"`
}

type texture struct {
	URL      string           `json:"url"`
	Metadata *textureMetadata `json:"model,omitempty"`
}

type textureMap struct {
	Skin *texture `json:"SKIN,omitempty"`
	Cape *texture `json:"CAPE,omitempty"`
}

type texturesValue struct {
	Timestamp   int64      `json:"timestamp"`
	ProfileID   string     `json:"profileId"`
	ProfileName string     `json:"profileName"`
	Textures    textureMap `json:"textures"`
}

func fullProfile(app *App, user *User, sign bool) (profileResponse, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return profileResponse{}, err
	}

	var skinTexture *texture
	if user.SkinHash.Valid {
		skinTexture = &texture{
			URL: SkinURL(app, user.SkinHash.String),
			Metadata: &textureMetadata{
				Model: user.SkinModel,
			},
		}
	}

	var capeTexture *texture
	if user.CapeHash.Valid {
		capeTexture = &texture{
			URL: CapeURL(app, user.CapeHash.String),
		}
	}

	texturesValue := texturesValue{
		Timestamp:   time.Now().UnixNano(),
		ProfileID:   id,
		ProfileName: user.PlayerName,
		Textures: textureMap{
			Skin: skinTexture,
			Cape: capeTexture,
		},
	}
	texturesValueBlob, err := json.Marshal(texturesValue)
	if err != nil {
		return profileResponse{}, err
	}

	texturesValueBase64 := base64.StdEncoding.EncodeToString(texturesValueBlob)

	var texturesSignature *string
	if sign {
		signature, err := SignSHA1(app, []byte(texturesValueBase64))
		if err != nil {
			return profileResponse{}, err
		}
		signatureBase64 := base64.StdEncoding.EncodeToString(signature)
		texturesSignature = &signatureBase64
	}

	texturesProperty := profileProperty{
		Name:      "textures",
		Value:     texturesValueBase64,
		Signature: texturesSignature,
	}
	return profileResponse{
		ID:         id,
		Name:       user.PlayerName,
		Properties: []profileProperty{texturesProperty},
	}, nil
}

// /session/minecraft/hasJoined
func SessionHasJoined(app *App) func(c echo.Context) error {
	type ProfileProperty struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		Signature string `json:"signature"`
	}
	type HasJoinedResponse struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Properties []ProfileProperty `json:"properties"`
	}
	return func(c echo.Context) error {
		playerName := c.QueryParam("username")
		serverID := c.QueryParam("serverId")

		var user User
		result := app.DB.First(&user, "player_name = ?", playerName)
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return c.NoContent(http.StatusForbidden)
		}

		if result.Error != nil || !user.ServerID.Valid || serverID != user.ServerID.String {
			for _, fallbackSessionServer := range app.Config.FallbackSessionServers {
				fmt.Println("falling back to", fallbackSessionServer)
				base, err := url.Parse(fallbackSessionServer)
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
