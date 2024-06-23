package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"net/http"
)

/*
Authentication server
*/

type UserProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type UserResponse struct {
	ID         string         `json:"id"`
	Properties []UserProperty `json:"properties"`
}

var invalidCredentialsBlob []byte = Unwrap(json.Marshal(ErrorResponse{
	Error:        Ptr("ForbiddenOperationException"),
	ErrorMessage: Ptr("Invalid credentials. Invalid username or password."),
}))
var invalidAccessTokenBlob []byte = Unwrap(json.Marshal(ErrorResponse{
	Error:        Ptr("ForbiddenOperationException"),
	ErrorMessage: Ptr("Invalid token."),
}))

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

// POST /authenticate
// https://wiki.vg/Legacy_Mojang_Authentication#Authenticate
func AuthAuthenticate(app *App) func(c echo.Context) error {
	return func(c echo.Context) (err error) {
		req := new(authenticateRequest)
		if err = c.Bind(req); err != nil {
			return err
		}

		username := req.Username
		doTransientLogin := app.TransientLoginEligible(username)

		var user User
		result := app.DB.Preload("Clients").First(&user, "username = ?", username)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				if doTransientLogin {
					user, err = MakeTransientUser(app, username)
					if err != nil {
						return err
					}

					result := app.DB.Create(&user)
					if result.Error != nil {
						return result.Error
					}
				} else {
					return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
				}
			} else {
				return result.Error
			}
		}

		if doTransientLogin {
			if req.Password != app.Config.TransientUsers.Password {
				return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
			}
		} else {
			passwordHash, err := HashPassword(req.Password, user.PasswordSalt)
			if err != nil {
				return err
			}

			if !bytes.Equal(passwordHash, user.PasswordHash) {
				return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
			}
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
				} else {
					if !app.Config.AllowMultipleAccessTokens {
						user.Clients[i].Version += 1
					}
				}
			}

			if !clientExists {
				client = Client{
					UUID:        uuid.New().String(),
					ClientToken: clientToken,
					Version:     0,
				}
				user.Clients = append(user.Clients, client)
			}
		}

		// Save changes to user.Clients
		result = app.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(&user)
		if result.Error != nil {
			return result.Error
		}

		id, err := UUIDToID(user.UUID)
		if err != nil {
			return err
		}

		var selectedProfile *Profile
		var availableProfiles *[]Profile
		if req.Agent != nil {
			selectedProfile = &Profile{
				ID:   id,
				Name: user.PlayerName,
			}
			availableProfiles = &[]Profile{*selectedProfile}
		}

		var userResponse *UserResponse
		if req.RequestUser {
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
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
	RequestUser bool   `json:"requestUser"`
}
type refreshResponse struct {
	AccessToken       string        `json:"accessToken"`
	ClientToken       string        `json:"clientToken"`
	SelectedProfile   Profile       `json:"selectedProfile,omitempty"`
	AvailableProfiles []Profile     `json:"availableProfiles,omitempty"`
	User              *UserResponse `json:"user,omitempty"`
}

// POST /refresh
// https://wiki.vg/Legacy_Mojang_Authentication#Refresh
func AuthRefresh(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(refreshRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyAllow)
		if client == nil || client.ClientToken != req.ClientToken {
			return c.JSONBlob(http.StatusUnauthorized, invalidAccessTokenBlob)
		}
		user := client.User

		id, err := UUIDToID(user.UUID)
		if err != nil {
			return err
		}

		selectedProfile := Profile{
			ID:   id,
			Name: user.PlayerName,
		}
		availableProfiles := []Profile{selectedProfile}

		var userResponse *UserResponse
		if req.RequestUser {
			userResponse = &UserResponse{
				ID: id,
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

		result := app.DB.Save(client)
		if result.Error != nil {
			return result.Error
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
// https://wiki.vg/Legacy_Mojang_Authentication#Validate
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
// https://wiki.vg/Legacy_Mojang_Authentication#Signout
func AuthSignout(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(signoutRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var user User
		result := app.DB.First(&user, "username = ?", req.Username)
		if result.Error != nil {
			return result.Error
		}

		passwordHash, err := HashPassword(req.Password, user.PasswordSalt)
		if err != nil {
			return err
		}

		if !bytes.Equal(passwordHash, user.PasswordHash) {
			return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
		}

		err = app.InvalidateUser(&user)
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
// https://wiki.vg/Legacy_Mojang_Authentication#Invalidate
func AuthInvalidate(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		req := new(invalidateRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		client := app.GetClient(req.AccessToken, StalePolicyAllow)
		if client == nil || client.ClientToken != req.ClientToken {
			return c.JSONBlob(http.StatusUnauthorized, invalidAccessTokenBlob)
		}

		err := app.InvalidateUser(&client.User)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	}
}
