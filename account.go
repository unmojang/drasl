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
// https://minecraft.wiki/w/Mojang_API#Query_player's_UUID
func AccountPlayerNameToID(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.Param("playerName")

		var player Player
		result := app.DB.First(&player, "name = ?", playerName)
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

		id, err := UUIDToID(player.UUID)
		if err != nil {
			return err
		}
		res := playerNameToUUIDResponse{
			Name: player.Name,
			ID:   id,
		}

		return c.JSON(http.StatusOK, res)
	}
}

// POST /profiles/minecraft
// POST /minecraft/profile/lookup/bulk/byname
// https://minecraft.wiki/w/Mojang_API#Query_player_UUIDs_in_batch
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
			var player Player
			result := app.DB.First(&player, "name = ?", playerName)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					remainingPlayers[strings.ToLower(playerName)] = true
				} else {
					return result.Error
				}
			} else {
				id, err := UUIDToID(player.UUID)
				if err != nil {
					return err
				}
				playerRes := playerNameToUUIDResponse{
					Name: player.Name,
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
func AccountVerifySecurityLocation(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}

func AccountUploadSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, player *Player) error {
		// Detect if the request was made from the Authlib-Injector URL
		fromAuthlibInjector := strings.HasPrefix(c.Request().RequestURI, "/authlib-injector")
		if !fromAuthlibInjector {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("This is an Authlib-Injector endpoint only"))
		}

		if !app.Config.AllowSkins || !app.Config.EnableAuthlibSkinAPI {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Changing your skin is not allowed."))
		}

		model := strings.ToLower(c.FormValue("model"))
		if model != "slim" && model != "" {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Invalid request body for skin upload"))
		}
		player.SkinModel = model

		file, err := c.FormFile("file")
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Invalid request body for skin upload"))
		}
		src, err := file.Open()
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Could not read Skin data"))
		}
		defer src.Close()

		if err := app.SetSkinAndSave(player, src); err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("The skin could not be processed"))
		}

		return c.NoContent(http.StatusNoContent)
	})
}

func AccountUploadCape(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, player *Player) error {
		// Detect if the request was made from the Authlib-Injector URL
		fromAuthlibInjector := strings.HasPrefix(c.Request().RequestURI, "/authlib-injector")
		if !fromAuthlibInjector {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("This is an Authlib-Injector endpoint only"))
		}

		if !app.Config.AllowCapes || !app.Config.EnableAuthlibSkinAPI {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Changing your Cape is not allowed."))
		}

		file, err := c.FormFile("file")
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Invalid request body for Cape upload"))
		}
		src, err := file.Open()
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Could not read Cape data"))
		}
		defer src.Close()

		if err := app.SetCapeAndSave(player, src); err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("The Cape could not be processed"))
		}

		return c.NoContent(http.StatusNoContent)
	})
}

func AccountDeleteSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, player *Player) error {
		// Detect if the request was made from the Authlib-Injector URL
		fromAuthlibInjector := strings.HasPrefix(c.Request().RequestURI, "/authlib-injector")
		if !fromAuthlibInjector {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("This is an Authlib-Injector endpoint only"))
		}

		err := app.SetSkinAndSave(player, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}

func AccountDeleteCape(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, player *Player) error {
		// Detect if the request was made from the Authlib-Injector URL
		fromAuthlibInjector := strings.HasPrefix(c.Request().RequestURI, "/authlib-injector")
		if !fromAuthlibInjector {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("This is an Authlib-Injector endpoint only"))
		}
		
		err := app.SetCapeAndSave(player, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}
