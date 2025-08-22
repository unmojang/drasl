package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"gorm.io/gorm"
	"net/http"
)

/*
Authentication server
*/

func getAvailableProfiles(user *User) ([]Profile, error) {
	var availableProfiles []Profile
	for _, player := range user.Players {
		id, err := UUIDToID(player.UUID)
		if err != nil {
			return nil, err
		}
		availableProfiles = append(availableProfiles, Profile{
			ID:   id,
			Name: player.Name,
		})
	}
	return availableProfiles, nil
}

type UserProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type UserResponse struct {
	ID         string         `json:"id"`
	Properties []UserProperty `json:"properties"`
}

var invalidCredentialsError = &YggdrasilError{
	Code:         http.StatusUnauthorized,
	Error_:       mo.Some("ForbiddenOperationException"),
	ErrorMessage: mo.Some("Invalid credentials. Invalid username or password."),
}

var invalidAccessTokenError = &YggdrasilError{
	Code:         http.StatusForbidden,
	Error_:       mo.Some("ForbiddenOperationException"),
	ErrorMessage: mo.Some("Invalid token"),
}

var playerNotFoundError = &YggdrasilError{
	Code:         http.StatusBadRequest,
	Error_:       mo.Some("IllegalArgumentException"),
	ErrorMessage: mo.Some("Player not found."),
}

type serverInfoResponse struct {
	Status                 string `json:"Status"`
	RuntimeMode            string `json:"RuntimeMode"`
	ApplicationAuthor      string `json:"ApplicationAuthor"`
	ApplicationDescription string `json:"ApplcationDescription"`
	SpecificationVersion   string `json:"SpecificationVersion"`
	ImplementationVersion  string `json:"ImplementationVersion"`
	ApplicationOwner       string `json:"ApplicationOwner"`
}

// GET /
func AuthServerInfo(app *App) func(c echo.Context) error {
	info := serverInfoResponse{
		Status:                 "OK",
		RuntimeMode:            "productionMode",
		ApplicationAuthor:      "Unmojang",
		ApplicationDescription: "",
		SpecificationVersion:   "2.13.34",
		ImplementationVersion:  "0.1.0",
		ApplicationOwner:       app.Config.ApplicationOwner,
	}
	infoBlob := Unwrap(json.Marshal(info))
	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, infoBlob)
	}
}

type authenticateRequest struct {
	Username    string  `json:"username"`
	Password    string  `json:"password"`
	ClientToken *string `json:"clientToken"`
	Agent       *Agent  `json:"agent"`
	RequestUser bool    `json:"requestUser"`
}
type authenticateResponse struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	SelectedProfile   *Profile      `json:"selectedProfile,omitempty"`
	AvailableProfiles *[]Profile    `json:"availableProfiles,omitempty"`
	User              *UserResponse `json:"user,omitempty"`
}

func (app *App) AuthAuthenticateUser(c echo.Context, playerNameOrUsername string, password string) (*User, mo.Option[Player], error) {
	var user *User
	player := mo.None[Player]()

	var playerStruct Player
	if err := app.DB.Preload("User").First(&playerStruct, "name = ?", playerNameOrUsername).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			var userStruct User
			if err := app.DB.First(&userStruct, "username = ?", playerNameOrUsername).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, mo.None[Player](), invalidCredentialsError
				}
				return nil, mo.None[Player](), err
			}
			user = &userStruct
			if len(user.Players) == 1 {
				player = mo.Some(user.Players[0])
			}
		} else {
			return nil, mo.None[Player](), err
		}
	} else {
		// player query succeeded
		player = mo.Some(playerStruct)
		user = &player.ToPointer().User
	}

	if password == user.MinecraftToken {
		return user, player, nil
	}

	if !app.Config.AllowPasswordLogin || len(user.OIDCIdentities) > 0 {
		return nil, mo.None[Player](), invalidCredentialsError
	}

	passwordHash, err := HashPassword(password, user.PasswordSalt)
	if err != nil {
		return nil, mo.None[Player](), err
	}

	if !bytes.Equal(passwordHash, user.PasswordHash) {
		return nil, mo.None[Player](), invalidCredentialsError
	}

	if user.IsLocked {
		return nil, mo.None[Player](), invalidCredentialsError
	}

	return user, player, nil
}

// POST /authenticate
// https://minecraft.wiki/w/Yggdrasil#Authenticate
func AuthAuthenticate(app *App) func(c echo.Context) error {
	return func(c echo.Context) (err error) {
		req := new(authenticateRequest)
		if err = c.Bind(req); err != nil {
			return err
		}

		user, player, err := app.AuthAuthenticateUser(c, req.Username, req.Password)
		if err != nil {
			return err
		}

		playerUUID := mo.None[string]()
		if p, ok := player.Get(); ok {
			playerUUID = mo.Some(p.UUID)
		}

		var client Client
		if req.ClientToken == nil {
			clientToken, err := RandomHex(16)
			if err != nil {
				return err
			}
			client = Client{
				UUID:        uuid.New().String(),
				ClientToken: clientToken,
				Version:     0,
				PlayerUUID:  OptionToNullString(playerUUID),
			}
			user.Clients = append(user.Clients, client)
		} else {
			clientToken := *req.ClientToken
			clientExists := false

			for i := range user.Clients {
				if user.Clients[i].ClientToken == clientToken {
					clientExists = true
					user.Clients[i].Version += 1
					client = user.Clients[i]
					break
				}
			}

			if !clientExists {
				client = Client{
					UUID:        uuid.New().String(),
					ClientToken: clientToken,
					Version:     0,
					PlayerUUID:  OptionToNullString(playerUUID),
				}
				user.Clients = append(user.Clients, client)
			}
		}

		var selectedProfile *Profile = nil
		var availableProfiles *[]Profile = nil
		if req.Agent != nil {
			if p, ok := player.Get(); ok {
				id, err := UUIDToID(p.UUID)
				if err != nil {
					return err
				}
				selectedProfile = &Profile{
					ID:   id,
					Name: p.Name,
				}
			}
			availableProfilesArray, err := getAvailableProfiles(user)
			if err != nil {
				return err
			}
			availableProfiles = &availableProfilesArray
		}

		var userResponse *UserResponse
		if req.RequestUser {
			id, err := UUIDToID(user.UUID)
			if err != nil {
				return err
			}
			userResponse = &UserResponse{
				ID: id,
				Properties: []UserProperty{{
					Name:  "preferredLanguage",
					Value: user.PreferredLanguage,
				}},
			}
		}

		accessToken, err := app.MakeAccessToken(client)
		if err != nil {
			return err
		}

		// Save changes to user.Clients
		if err := app.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(&user).Error; err != nil {
			return err
		}

		res := authenticateResponse{
			ClientToken:       client.ClientToken,
			AccessToken:       accessToken,
			SelectedProfile:   selectedProfile,
			AvailableProfiles: availableProfiles,
			User:              userResponse,
		}
		return c.JSON(http.StatusOK, &res)
	}
}

type refreshRequest struct {
	AccessToken     string   `json:"accessToken"`
	ClientToken     string   `json:"clientToken"`
	RequestUser     bool     `json:"requestUser"`
	SelectedProfile *Profile `json:"selectedProfile"`
}
type refreshResponse struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	SelectedProfile   *Profile      `json:"selectedProfile,omitempty"`
	AvailableProfiles []Profile     `json:"availableProfiles,omitempty"`
	User              *UserResponse `json:"user,omitempty"`
}

// POST /refresh
// https://minecraft.wiki/w/Yggdrasil#Refresh
func AuthRefresh(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(refreshRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyAllow)
		if client == nil || client.ClientToken != req.ClientToken {
			return invalidAccessTokenError
		}
		user := client.User
		player := client.Player

		if req.SelectedProfile != nil {
			if player == nil {
				// Just ignore if there is already a selectedProfile for the
				// client
				for _, userPlayer := range user.Players {
					requestedUUID, err := IDToUUID(req.SelectedProfile.ID)
					if err != nil {
						return err
					}
					if userPlayer.UUID == requestedUUID {
						client.PlayerUUID = MakeNullString(&userPlayer.UUID)
						player = &userPlayer
						break
					}
				}
				if player == nil {
					return playerNotFoundError
				}
			}
		}

		var selectedProfile *Profile = nil
		if player != nil {
			id, err := UUIDToID(player.UUID)
			if err != nil {
				return err
			}
			selectedProfile = &Profile{
				ID:   id,
				Name: player.Name,
			}
		}
		availableProfiles, err := getAvailableProfiles(&user)
		if err != nil {
			return err
		}

		var userResponse *UserResponse
		if req.RequestUser && selectedProfile != nil {
			userResponse = &UserResponse{
				ID: selectedProfile.ID,
				Properties: []UserProperty{{
					Name:  "preferredLanguage",
					Value: user.PreferredLanguage,
				}},
			}
		}

		client.Version += 1
		accessToken, err := app.MakeAccessToken(*client)
		if err != nil {
			return err
		}

		if err := app.DB.Save(client).Error; err != nil {
			return err
		}

		res := refreshResponse{
			AccessToken:       accessToken,
			ClientToken:       client.ClientToken,
			SelectedProfile:   selectedProfile,
			AvailableProfiles: availableProfiles,
			User:              userResponse,
		}

		return c.JSON(http.StatusOK, &res)
	}
}

type validateRequest struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

// POST /validate
// https://minecraft.wiki/w/Yggdrasil#Validate
func AuthValidate(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(validateRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyDeny)
		if client == nil || client.ClientToken != req.ClientToken {
			return c.NoContent(http.StatusForbidden)
		}

		return c.NoContent(http.StatusNoContent)
	}
}

type signoutRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// POST /signout
// https://minecraft.wiki/w/Yggdrasil#Signout
func AuthSignout(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(signoutRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		user, _, err := app.AuthAuthenticateUser(c, req.Username, req.Password)
		if err != nil {
			return err
		}

		err = app.InvalidateUser(app.DB, user)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	}
}

type invalidateRequest struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

// POST /invalidate
// https://minecraft.wiki/w/Yggdrasil#Invalidate
func AuthInvalidate(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(invalidateRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyAllow)
		if client == nil {
			return invalidAccessTokenError
		}

		if client.Player == nil {
			err := app.InvalidateUser(app.DB, &client.User)
			if err != nil {
				return err
			}
		} else {
			err := app.InvalidatePlayer(app.DB, client.Player)
			if err != nil {
				return err
			}
		}

		return c.NoContent(http.StatusNoContent)
	}
}
