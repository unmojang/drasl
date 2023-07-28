package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
var invalidClientTokenBlob []byte = Unwrap(json.Marshal(ErrorResponse{
	Error: Ptr("ForbiddenOperationException"),
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
		doAnonymousLogin := AnonymousLoginEligible(app, username)

		var user User
		result := app.DB.Preload("TokenPairs").First(&user, "username = ?", username)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				if doAnonymousLogin {
					if req.Password != app.Config.AnonymousLogin.Password {
						return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
					}
					user, err = MakeAnonymousUser(app, username)
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

		passwordHash, err := HashPassword(req.Password, user.PasswordSalt)
		if err != nil {
			return err
		}

		if !bytes.Equal(passwordHash, user.PasswordHash) {
			return c.JSONBlob(http.StatusUnauthorized, invalidCredentialsBlob)
		}

		var tokenPair TokenPair

		// TODO use proper HMAC JWTs?
		accessToken, err := RandomHex(16)
		if err != nil {
			return err
		}

		if req.ClientToken == nil {
			clientToken, err := RandomHex(16)
			if err != nil {
				return err
			}
			tokenPair = TokenPair{
				ClientToken: clientToken,
				AccessToken: accessToken,
				Valid:       true,
			}
			user.TokenPairs = append(user.TokenPairs, tokenPair)
		} else {
			clientToken := *req.ClientToken
			clientTokenExists := false
			for i := range user.TokenPairs {
				if user.TokenPairs[i].ClientToken == clientToken {
					clientTokenExists = true
					user.TokenPairs[i].AccessToken = accessToken
					user.TokenPairs[i].Valid = true
					tokenPair = user.TokenPairs[i]
					break
				} else {
					if app.Config.EnableTokenExpiry {
						user.TokenPairs[i].Valid = false
					}
				}
			}

			if !clientTokenExists {
				tokenPair = TokenPair{
					ClientToken: clientToken,
					AccessToken: accessToken,
					Valid:       true,
				}
				user.TokenPairs = append(user.TokenPairs, tokenPair)
			}
		}

		result = app.DB.Save(&user)
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

		res := authenticateResponse{
			ClientToken:       tokenPair.ClientToken,
			AccessToken:       tokenPair.AccessToken,
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

		var tokenPair TokenPair
		result := app.DB.Preload("User").First(&tokenPair, "client_token = ?", req.ClientToken)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.JSONBlob(http.StatusUnauthorized, invalidClientTokenBlob)
			}
			return result.Error
		}
		user := tokenPair.User

		if !tokenPair.Valid || req.AccessToken != tokenPair.AccessToken {
			return c.JSONBlob(http.StatusUnauthorized, invalidAccessTokenBlob)
		}

		accessToken, err := RandomHex(16)
		if err != nil {
			return err
		}
		tokenPair.AccessToken = accessToken
		tokenPair.Valid = true

		result = app.DB.Save(&tokenPair)
		if result.Error != nil {
			return result.Error
		}

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

		res := refreshResponse{
			AccessToken:       accessToken,
			ClientToken:       req.ClientToken,
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

		var tokenPair TokenPair
		result := app.DB.First(&tokenPair, "client_token = ?", req.ClientToken)
		if result.Error != nil {
			return c.NoContent(http.StatusForbidden)
		}

		if !tokenPair.Valid || req.AccessToken != tokenPair.AccessToken {
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

		update := map[string]interface{}{"valid": false}
		result = app.DB.Model(TokenPair{}).Where("user_uuid = ?", user.UUID).Updates(update)
		if result.Error != nil {
			return result.Error
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

		var tokenPair TokenPair
		result := app.DB.First(&tokenPair, "client_token = ?", req.ClientToken)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.JSONBlob(http.StatusUnauthorized, invalidClientTokenBlob)
			}
			return result.Error
		}

		if req.AccessToken != tokenPair.AccessToken {
			return c.JSONBlob(http.StatusUnauthorized, invalidAccessTokenBlob)
		}

		result = app.DB.Table("token_pairs").Where("user_uuid = ?", tokenPair.UserUUID).Updates(map[string]interface{}{"Valid": false})
		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	}
}
