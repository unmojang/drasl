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

func AuthGetServerInfo(app *App) func(c echo.Context) error {
	infoMap := make(map[string]string)
	infoMap["Status"] = "OK"
	infoMap["RuntimeMode"] = "productionMode"
	infoMap["ApplicationAuthor"] = "Unmojang"
	infoMap["ApplicationDescription"] = ""
	infoMap["SpecificationVersion"] = "2.13.34"
	infoMap["ImplementationVersion"] = "0.1.0"
	infoMap["ApplicationOwner"] = app.Config.ApplicationOwner

	infoBlob, err := json.Marshal(infoMap)
	Check(err)

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

func AuthAuthenticate(app *App) func(c echo.Context) error {
	invalidCredentialsBlob, err := json.Marshal(ErrorResponse{
		Error:        "ForbiddenOperationException",
		ErrorMessage: "Invalid credentials. Invalid username or password.",
	})
	Check(err)

	return func(c echo.Context) (err error) {
		AddAuthlibInjectorHeader(app, &c)

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

		var selectedProfile *Profile
		var availableProfiles *[]Profile
		if req.Agent != nil {
			id, err := UUIDToID(user.UUID)
			if err != nil {
				return err
			}
			selectedProfile = &Profile{
				ID:   id,
				Name: user.PlayerName,
			}
			availableProfiles = &[]Profile{*selectedProfile}
		}

		var userResponse *UserResponse
		if req.RequestUser {
			id, err := UUIDToID(user.UUID)
			if err != nil {
				return err
			}
			userResponse = &UserResponse{
				ID: id,
				Properties: []UserProperty{UserProperty{
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

type UserProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type UserResponse struct {
	ID         string         `json:"id"`
	Properties []UserProperty `json:"properties"`
}

func AuthRefresh(app *App) func(c echo.Context) error {
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

	invalidAccessTokenBlob, err := json.Marshal(ErrorResponse{
		Error:        "ForbiddenOperationException",
		ErrorMessage: "Invalid token.",
	})
	Check(err)

	return func(c echo.Context) error {
		AddAuthlibInjectorHeader(app, &c)

		req := new(refreshRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var tokenPair TokenPair
		result := app.DB.Preload("User").First(&tokenPair, "client_token = ?", req.ClientToken)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.NoContent(http.StatusUnauthorized)
			}
			return result.Error
		}
		user := tokenPair.User

		if req.AccessToken != tokenPair.AccessToken {
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

func AuthValidate(app *App) func(c echo.Context) error {
	type validateRequest struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
	}
	return func(c echo.Context) error {
		AddAuthlibInjectorHeader(app, &c)

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

func AuthSignout(app *App) func(c echo.Context) error {
	type signoutRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	invalidCredentialsBlob, err := json.Marshal(ErrorResponse{
		Error:        "ForbiddenOperationException",
		ErrorMessage: "Invalid credentials. Invalid username or password.",
	})
	Check(err)

	return func(c echo.Context) error {
		AddAuthlibInjectorHeader(app, &c)

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

		app.DB.Model(TokenPair{}).Where("user_uuid = ?", user.UUID).Updates(TokenPair{Valid: false})

		if result.Error != nil {
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	}
}

func AuthInvalidate(app *App) func(c echo.Context) error {
	type invalidateRequest struct {
		AccessToken string `json:"accessToken"`
		ClientToken string `json:"clientToken"`
	}

	invalidAccessTokenBlob, err := json.Marshal(ErrorResponse{
		Error:        "ForbiddenOperationException",
		ErrorMessage: "Invalid token.",
	})
	Check(err)

	return func(c echo.Context) error {
		AddAuthlibInjectorHeader(app, &c)

		req := new(invalidateRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var tokenPair TokenPair
		result := app.DB.First(&tokenPair, "client_token = ?", req.ClientToken)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.JSONBlob(http.StatusUnauthorized, invalidAccessTokenBlob)
			}
			return result.Error
		}
		app.DB.Table("token_pairs").Where("user_uuid = ?", tokenPair.UserUUID).Updates(map[string]interface{}{"Valid": false})

		return c.NoContent(http.StatusNoContent)
	}
}
