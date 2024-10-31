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
	"strings"
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
					reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "profiles/minecraft")
					if err != nil {
						log.Println(err)
						continue
					}

					payload := []string{playerName}
					body, err := json.Marshal(payload)
					if err != nil {
						return err
					}

					res, err := app.CachedPostJSON(reqURL, body, fallbackAPIServer.CacheTTLSeconds)
					if err != nil {
						log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
						continue
					}
					if res.StatusCode != http.StatusOK {
						continue
					}

					var fallbackResponses []playerNameToUUIDResponse
					err = json.Unmarshal(res.BodyBytes, &fallbackResponses)
					if err != nil {
						log.Printf("Received invalid response from fallback API server at %s\n", reqURL)
						continue
					}
					if len(fallbackResponses) == 1 && strings.EqualFold(playerName, fallbackResponses[0].Name) {
						return c.JSON(http.StatusOK, fallbackResponses[0])
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
// POST /minecraft/profile/lookup/bulk/byname
// https://wiki.vg/Mojang_API#Usernames_to_UUIDs
func AccountPlayerNamesToIDs(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		var playerNames []string
		if err := json.NewDecoder(c.Request().Body).Decode(&playerNames); err != nil {
			return err
		}

		n := len(playerNames)
		if !(1 <= n && n <= 10) {
			return MakeErrorResponse(&c, http.StatusBadRequest, Ptr("CONSTRAINT_VIOLATION"), Ptr("getProfileName.profileNames: size must be between 1 and 10"))
		}

		response := make([]playerNameToUUIDResponse, 0, n)

		remainingPlayers := map[string]bool{}
		for _, playerName := range playerNames {
			var user User
			result := app.DB.First(&user, "player_name = ?", playerName)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					remainingPlayers[strings.ToLower(playerName)] = true
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

		for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
			reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "profiles/minecraft")
			if err != nil {
				log.Println(err)
				continue
			}

			payload := make([]string, 0, len(remainingPlayers))
			for remainingPlayer := range remainingPlayers {
				payload = append(payload, remainingPlayer)
			}
			body, err := json.Marshal(payload)
			if err != nil {
				return err
			}

			res, err := app.CachedPostJSON(reqURL, body, fallbackAPIServer.CacheTTLSeconds)
			if err != nil {
				log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
				continue
			}

			if res.StatusCode != http.StatusOK {
				continue
			}

			var fallbackResponses []playerNameToUUIDResponse
			err = json.Unmarshal(res.BodyBytes, &fallbackResponses)
			if err != nil {
				log.Printf("Received invalid response from fallback API server at %s\n", reqURL)
				continue
			}

			for _, fallbackResponse := range fallbackResponses {
				lowerName := strings.ToLower(fallbackResponse.Name)
				if _, ok := remainingPlayers[lowerName]; ok {
					response = append(response, fallbackResponse)
					delete(remainingPlayers, lowerName)
				}
			}

			if len(remainingPlayers) == 0 {
				break
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
