package main

import (
	"encoding/json"
	"errors"
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

// /users/profiles/minecraft/:playerName
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
					res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTL)
					if err != nil {
						log.Println(err)
						continue
					}

					if res.StatusCode == http.StatusOK {
						return c.Blob(http.StatusOK, "application/json", res.BodyBytes)
					}
				}
				return c.NoContent(http.StatusNoContent)
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

// /profiles/minecraft
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
						res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTL)
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

// /user/security/location
func AccountVerifySecurityLocation(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}
