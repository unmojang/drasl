package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v5"
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
	Code:         http.StatusForbidden,
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
func AuthServerInfo(app *App) func(c *echo.Context) error {
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
	return func(c *echo.Context) error {
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

func (app *App) AuthAuthenticateUser(c *echo.Context, playerNameOrUsername string, password string) (*User, mo.Option[Player], error) {
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
func AuthAuthenticate(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) (err error) {
		req := new(authenticateRequest)
		if err = c.Bind(req); err != nil {
			return err
		}

		user, maybePlayer, err := app.AuthAuthenticateUser(c, req.Username, req.Password)
		if err != nil {
			return err
		}

		tx := app.DB.Begin()
		defer tx.Rollback()

		var client Client
		if req.ClientToken == nil {
			clientToken, err := RandomHex(16)
			if err != nil {
				return err
			}

			playerUUID := mo.None[string]()
			if player, ok := maybePlayer.Get(); ok {
				playerUUID = mo.Some(player.UUID)
			}
			client = NewClient(user, clientToken, playerUUID)
			if err := tx.Create(&client).Error; err != nil {
				return err
			}
		} else {
			clientToken := *req.ClientToken

			if err := tx.Preload("Player").First(&client, "user_uuid = ? AND client_token = ?", user.UUID, clientToken).Error; err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				// Client does not exist
				playerUUID := mo.None[string]()
				if player, ok := maybePlayer.Get(); ok {
					playerUUID = mo.Some(player.UUID)
				}
				client = NewClient(user, clientToken, playerUUID)
				if err := tx.Create(&client).Error; err != nil {
					return err
				}
			} else {
				// Client exists
				client.Version += 1
				if player, ok := maybePlayer.Get(); ok {
					client.Player = &player
				} else {
					client.PlayerUUID = MakeNullString(nil)
					client.Player = nil
				}
				if err := tx.Save(&client).Error; err != nil {
					return err
				}
				maybePlayer = mo.PointerToOption(client.Player)
			}
		}

		var selectedProfile *Profile = nil
		var availableProfiles *[]Profile = nil
		if req.Agent != nil {
			if player, ok := maybePlayer.Get(); ok {
				id, err := UUIDToID(player.UUID)
				if err != nil {
					return err
				}
				selectedProfile = &Profile{
					ID:   id,
					Name: player.Name,
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

		if err := tx.Commit().Error; err != nil {
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

// Perform request validation and authentication for AuthRefresh
func (app *App) BindAuthRefresh() func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := new(refreshRequest)
			if err := c.Bind(req); err != nil {
				return err
			}

			client, err := app.GetClient(req.AccessToken, mo.Some(req.ClientToken), StalePolicyAllow, false)
			var userError *UserError
			if err != nil {
				if errors.As(err, &userError) {
					return invalidAccessTokenError
				} else {
					return err
				}
			}
			maybeUser := mo.Some(client.User)
			c.Set(CONTEXT_KEY_REQ, req)
			c.Set(CONTEXT_KEY_CLIENT, client)
			c.Set(CONTEXT_KEY_MAYBE_USER, maybeUser)
			c.Set(CONTEXT_KEY_USER, maybeUser.ToPointer())
			c.Set(CONTEXT_KEY_MAYBE_PLAYER, mo.PointerToOption(client.Player))
			return next(c)
		}
	}
}

// POST /refresh
// https://minecraft.wiki/w/Yggdrasil#Refresh
func AuthRefresh(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		req := c.Get(CONTEXT_KEY_REQ).(*refreshRequest)
		client := c.Get(CONTEXT_KEY_CLIENT).(*Client)
		user := c.Get(CONTEXT_KEY_USER).(*User)
		maybePlayer := c.Get(CONTEXT_KEY_MAYBE_PLAYER).(mo.Option[Player])

		// Just ignore if there is already a selectedProfile for the
		// client
		if req.SelectedProfile != nil {
			if maybePlayer.IsAbsent() {
				for _, userPlayer := range user.Players {
					requestedUUID, err := IDToUUID(req.SelectedProfile.ID)
					if err != nil {
						return err
					}
					if userPlayer.UUID == requestedUUID {
						client.PlayerUUID = MakeNullString(&userPlayer.UUID)
						maybePlayer = mo.Some(userPlayer)
						break
					}
				}
				if maybePlayer.IsAbsent() {
					return playerNotFoundError
				}
			}
		}

		var selectedProfile *Profile = nil
		if player, ok := maybePlayer.Get(); ok {
			id, err := UUIDToID(player.UUID)
			if err != nil {
				return err
			}
			selectedProfile = &Profile{
				ID:   id,
				Name: player.Name,
			}
		}
		availableProfiles, err := getAvailableProfiles(user)
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

// Perform request validation and authentication for AuthValidate
func (app *App) BindAuthValidate() func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := new(validateRequest)
			if err := c.Bind(req); err != nil {
				return err
			}

			client, err := app.GetClient(req.AccessToken, mo.Some(req.ClientToken), StalePolicyAllow, false)
			var userError *UserError
			if err != nil && !errors.As(err, &userError) {
				return err
			}
			if err != nil {
				return invalidAccessTokenError
			}
			maybeUser := mo.Some(client.User)
			c.Set(CONTEXT_KEY_REQ, req)
			c.Set(CONTEXT_KEY_CLIENT, client)
			c.Set(CONTEXT_KEY_MAYBE_USER, maybeUser)
			c.Set(CONTEXT_KEY_USER, maybeUser.ToPointer())
			c.Set(CONTEXT_KEY_MAYBE_PLAYER, mo.PointerToOption(client.Player))
			return next(c)
		}
	}
}

// POST /validate
// https://minecraft.wiki/w/Yggdrasil#Validate
func AuthValidate(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}

type signoutRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// POST /signout
// https://minecraft.wiki/w/Yggdrasil#Signout
func AuthSignout(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
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

// Perform request validation and authentication for AuthInvalidate
func (app *App) BindAuthInvalidate() func(echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := new(validateRequest)
			if err := c.Bind(req); err != nil {
				return err
			}

			client, err := app.GetClient(req.AccessToken, mo.Some(req.ClientToken), StalePolicyAllow, false)
			var userError *UserError
			if err != nil && !errors.As(err, &userError) {
				return err
			}
			if err != nil {
				return invalidAccessTokenError
			}
			maybeUser := mo.Some(client.User)
			c.Set(CONTEXT_KEY_REQ, req)
			c.Set(CONTEXT_KEY_CLIENT, client)
			c.Set(CONTEXT_KEY_MAYBE_USER, maybeUser)
			c.Set(CONTEXT_KEY_USER, maybeUser.ToPointer())
			c.Set(CONTEXT_KEY_MAYBE_PLAYER, mo.PointerToOption(client.Player))
			return next(c)
		}
	}
}

// POST /invalidate
// https://minecraft.wiki/w/Yggdrasil#Invalidate
func AuthInvalidate(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		user := c.Get(CONTEXT_KEY_USER).(*User)
		maybePlayer := c.Get(CONTEXT_KEY_MAYBE_PLAYER).(mo.Option[Player])
		if player, ok := maybePlayer.Get(); ok {
			err := app.InvalidatePlayer(app.DB, &player)
			if err != nil {
				return err
			}
		} else {
			err := app.InvalidateUser(app.DB, user)
			if err != nil {
				return err
			}
		}
		return c.NoContent(http.StatusNoContent)
	}
}
