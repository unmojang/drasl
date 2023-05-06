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

// /profiles/minecraft/:playerName
func AccountPlayerNameToUUID(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.Param("playerName")

		var user User
		result := app.DB.First(&user, "player_name = ?", playerName)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
					reqURL, err := url.JoinPath(fallbackAPIServer.SessionURL, playerName)
					if err != nil {
						log.Println(err)
						continue
					}
					res, err := http.Get(reqURL)
					if err != nil {
						log.Println(err)
						continue
					}
					defer res.Body.Close()

					if res.StatusCode == http.StatusOK {
						return c.Stream(http.StatusOK, res.Header.Get("Content-Type"), res.Body)
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
func AccountPlayerNamesToUUIDs(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		// playerNames := &[]string{}
		var playerNames []string
		if err := json.NewDecoder(c.Request().Body).Decode(&playerNames); err != nil {
			return err
		}

		n := len(playerNames)
		res := make([]playerNameToUUIDResponse, 0, n)

		for _, playerName := range playerNames {
			var user User
			result := app.DB.First(&user, "player_name = ?", playerName)
			if result.Error != nil {
				if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
					// TODO fallback servers
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
				res = append(res, playerRes)
			}
		}

		return c.JSON(http.StatusOK, res)
	}
}

func AccountVerifySecurityLocation(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}
