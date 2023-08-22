package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/url"
)

type playerNameToUUIDResponse struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// GET /users/profiles/minecraft/:playerName
// https://wiki.vg/Mojang_API#Username_to_UUID
func AccountPlayerNameToID(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.Param("playerName")

		var user User
		result := app.DB.First(&user, "player_name = ?", playerName)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
					reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "users/profiles/minecraft", playerName)
					if err != nil {
						log.Println(err)
						continue
					}
					res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTLSeconds)
					if err != nil {
						log.Println(err)
						continue
					}

					if res.StatusCode == http.StatusOK {
						return c.Blob(http.StatusOK, "application/json", res.BodyBytes)
					}
				}
				errorMessage := fmt.Sprintf("Couldn't find any profile with name %s", playerName)
				return MakeErrorResponse(&c, http.StatusNotFound, nil, Ptr(errorMessage))
			}
			return result.Error
		}

		id, err := UUIDToID(user.UUID)
		if err != nil {
			return err
		}
		res := playerNameToUUIDResponse{
			Name: user.PlayerName,
			ID:   id,
		}

		return c.JSON(http.StatusOK, res)
	}
}

// POST /profiles/minecraft
// https://wiki.vg/Mojang_API#Usernames_to_UUIDs
func AccountPlayerNamesToIDs(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		// playerNames := &[]string{}
		var playerNames []string
		if err := json.NewDecoder(c.Request().Body).Decode(&playerNames); err != nil {
			return err
		}

		n := len(playerNames)
		response := make([]playerNameToUUIDResponse, 0, n)

		for _, playerName := range playerNames {
			var user User
			result := app.DB.First(&user, "player_name = ?", playerName)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
						reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "users/profiles/minecraft", playerName)
						if err != nil {
							log.Println(err)
							continue
						}
						res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTLSeconds)
						if err != nil {
							log.Println(err)
							continue
						}

						if res.StatusCode == http.StatusOK {
							var playerRes playerNameToUUIDResponse
							err = json.Unmarshal(res.BodyBytes, &playerRes)
							if err != nil {
								continue
							}
							response = append(response, playerRes)
							break
						}
					}
				} else {
					return result.Error
				}
			} else {
				id, err := UUIDToID(user.UUID)
				if err != nil {
					return err
				}
				playerRes := playerNameToUUIDResponse{
					Name: user.PlayerName,
					ID:   id,
				}
				response = append(response, playerRes)
			}
		}

		return c.JSON(http.StatusOK, response)
	}
}

// GET /user/security/location
// https://wiki.vg/Mojang_API#Verify_Security_Location
func AccountVerifySecurityLocation(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}
