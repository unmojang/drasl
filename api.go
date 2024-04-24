package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//	@title		Drasl API
//	@version	1.0

//	@contact.name	Unmojang
//	@contact.url	https://github.com/unmojang/drasl

//	@license.name	GPLv3
//	@license.url	https://www.gnu.org/licenses/gpl-3.0.en.html

type APIError struct {
	Message string `json:"message"`
}

func HandleAPIError(err error, c *echo.Context) error {
	code := http.StatusInternalServerError
	message := err.Error()
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		if m, ok := he.Message.(string); ok {
			message = m
		}
	}
	return (*c).JSON(code, APIError{Message: message})
}

func IsAPIPath(path_ string) bool {
	if path_ == "/" {
		return false
	}

	split := strings.Split(path_, "/")
	if len(split) >= 3 && split[1] == "drasl" && split[2] == "api" {
		return true
	}

	return false
}

func (app *App) withAPIToken(f func(c echo.Context, user *User) error) func(c echo.Context) error {
	bearerExp := regexp.MustCompile("^Bearer (.*)$")

	return func(c echo.Context) error {
		authorizationHeader := c.Request().Header.Get("Authorization")
		if authorizationHeader == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "Missing 'Bearer: abcdef' Authorization header")
		}

		tokenMatch := bearerExp.FindStringSubmatch(authorizationHeader)
		if tokenMatch == nil || len(tokenMatch) < 2 {
			return echo.NewHTTPError(http.StatusUnauthorized, "Malformed Authorization header")
		}
		token := tokenMatch[1]

		var user User
		if err := app.DB.First(&user, "api_token = ?", token).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusUnauthorized, "Unknown API token")
			}
			return err
		}

		return f(c, &user)
	}
}

func (app *App) withAPITokenAdmin(f func(c echo.Context, user *User) error) func(c echo.Context) error {
	notAnAdminBlob := Unwrap(json.Marshal(map[string]string{
		"error": "You are not an admin.",
	}))
	return app.withAPIToken(func(c echo.Context, user *User) error {
		if !user.IsAdmin {
			return c.JSONBlob(http.StatusForbidden, notAnAdminBlob)
		}
		return f(c, user)
	})
}

type APIUser struct {
	IsAdmin           bool      `json:"isAdmin"`
	IsLocked          bool      `json:"isLocked"`
	UUID              string    `json:"uuid"`
	Username          string    `json:"username"`
	PlayerName        string    `json:"playerName"`
	OfflineUUID       string    `json:"offlineUuid"`
	FallbackPlayer    string    `json:"fallbackPlayer"`
	PreferredLanguage string    `json:"preferredLanguage"`
	SkinURL           *string   `json:"skinUrl"`
	SkinModel         string    `json:"skinModel"`
	CapeURL           *string   `json:"capeUrl"`
	CreatedAt         time.Time `json:"createdAt"`
	NameLastChangedAt time.Time `json:"nameLastChangedAt"`
}

func (app *App) userToAPIUser(user *User) (APIUser, error) {
	skinURL, err := app.GetSkinURL(user)
	if err != nil {
		return APIUser{}, err
	}
	capeURL, err := app.GetCapeURL(user)
	if err != nil {
		return APIUser{}, err
	}
	return APIUser{
		IsAdmin:           user.IsAdmin,
		IsLocked:          user.IsLocked,
		UUID:              user.UUID,
		Username:          user.Username,
		PlayerName:        user.PlayerName,
		OfflineUUID:       user.OfflineUUID,
		FallbackPlayer:    user.FallbackPlayer,
		PreferredLanguage: user.PreferredLanguage,
		SkinURL:           skinURL,
		SkinModel:         user.SkinModel,
		CapeURL:           capeURL,
		CreatedAt:         user.CreatedAt,
		NameLastChangedAt: user.NameLastChangedAt,
	}, nil
}

type APIInvite struct {
	Code      string    `json:"code"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"createdAt"`
}

func (app *App) inviteToAPIInvite(invite *Invite) (APIInvite, error) {
	url, err := app.InviteURL(invite)
	if err != nil {
		return APIInvite{}, err
	}
	return APIInvite{
		Code:      invite.Code,
		URL:       url,
		CreatedAt: invite.CreatedAt,
	}, nil
}

// APIGetUsers godoc
//
//	@Summary		Get users
//	@Description	Get details of all users. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		APIUser
//	@Failure		403	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/users [get]
func (app *App) APIGetUsers() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		var users []User
		result := app.DB.Find(&users)
		if result.Error != nil {
			return result.Error
		}

		apiUsers := make([]APIUser, 0, len(users))
		for _, user := range users {
			apiUser, err := app.userToAPIUser(&user)
			if err != nil {
				return err
			}
			apiUsers = append(apiUsers, apiUser)
		}

		return c.JSON(http.StatusOK, apiUsers)
	})
}

// APIGetSelf godoc
//
//	@Summary		Get own account
//	@Description	Get account details of the user owning the API token.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIUser
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/user [get]
func (app *App) APIGetSelf() func(c echo.Context) error {
	return app.withAPIToken(func(c echo.Context, user *User) error {
		apiUser, err := app.userToAPIUser(user)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiUser)
	})
}

// APIGetUser godoc
//
//	@Summary		Get user by UUID
//	@Description	Get account details of a user by their UUID. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIUser
//	@Failure		400	{object}	APIError
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/users/{uuid} [get]
func (app *App) APIGetUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var profileUser User
		if err := app.DB.First(&profileUser, "uuid = ?", uuid_).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
			}
			return err
		}

		apiUser, err := app.userToAPIUser(&profileUser)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiUser)
	})
}

type createUserRequest struct {
	Username          string  `json:"username"`
	Password          string  `json:"password"`
	IsAdmin           bool    `json:"isAdmin"`
	IsLocked          bool    `json:"isLocked"`
	ChosenUUID        *string `json:"chosenUuid"`
	ExistingPlayer    bool    `json:"existingPlayer"`
	InviteCode        *string `json:"inviteCode"`
	PlayerName        *string `json:"playerName"`
	FallbackPlayer    *string `json:"fallbackPlayer"`
	PreferredLanguage *string `json:"preferredLanguage"`
	SkinModel         *string `json:"skinModel"`
	SkinBase64        *string `json:"skinBase64"`
	SkinURL           *string `json:"skinUrl"`
	CapeBase64        *string `json:"capeBase64"`
	CapeURL           *string `json:"capeUrl"`
}

// Create a user (admin only)
// APIGetUser godoc
//
//	@Summary		Create a new user
//	@Description	Create a new user. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			createUserRequest	body		createUserRequest	true	"Properties of the new user"
//	@Success		200					{object}	APIUser
//	@Failure		403					{object}	APIError
//	@Failure		500					{object}	APIError
//	@Router			/drasl/api/v1/users [post]
func (app *App) APICreateUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, caller *User) error {
		req := new(createUserRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var skinReader *io.Reader
		if req.SkinBase64 != nil {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(*req.SkinBase64))
			skinReader = &decoder
		}

		var capeReader *io.Reader
		if req.CapeBase64 != nil {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(*req.CapeBase64))
			capeReader = &decoder
		}

		user, err := app.CreateUser(
			caller,
			req.Username,
			req.Password,
			req.IsAdmin,
			req.IsLocked,
			req.ChosenUUID,
			req.ExistingPlayer,
			nil, // challengeToken
			req.InviteCode,
			req.PlayerName,
			req.FallbackPlayer,
			req.PreferredLanguage,
			req.SkinModel,
			skinReader,
			req.SkinURL,
			capeReader,
			req.CapeURL,
		)

		if err != nil {
			return err
		}

		apiUser, err := app.userToAPIUser(&user)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiUser)
	})
}

type updateUserRequest struct {
	Password          *string `json:"password"`
	IsAdmin           *bool   `json:"isAdmin"`
	IsLocked          *bool   `json:"isLocked"`
	PlayerName        *string `json:"playerName"`
	FallbackPlayer    *string `json:"fallbackPlayer"`
	ResetAPIToken     bool    `json:"resetApiToken"`
	PreferredLanguage *string `json:"preferredLanguage"`
	SkinModel         *string `json:"skinModel"`
	SkinBase64        *string `json:"skinBase64"`
	SkinURL           *string `json:"skinUrl"`
	DeleteSkin        bool    `json:"deleteSkin"`
	CapeBase64        *string `json:"capeBase64"`
	CapeURL           *string `json:"capeUrl"`
	DeleteCape        bool    `json:"deleteCape"`
}

// TODO PATCH update self

// APIGetUser godoc
//
//	@Summary		Update a user.
//	@Description	Update an existing user. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			updateUserRequest	body		updateUserRequest	true	"New properties of the user"
//	@Success		200					{object}	APIUser
//	@Failure		400					{object}	APIError
//	@Failure		403					{object}	APIError
//	@Failure		404					{object}	APIError
//	@Failure		500					{object}	APIError
//	@Router			/drasl/api/v1/users/{uuid} [patch]
func (app *App) APIUpdateUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, caller *User) error {
		req := new(updateUserRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var profileUser User
		if err := app.DB.First(&profileUser, "uuid = ?", uuid_).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
			}
			return err
		}

		var skinReader *io.Reader
		if req.SkinBase64 != nil {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(*req.SkinBase64))
			skinReader = &decoder
		}

		var capeReader *io.Reader
		if req.CapeBase64 != nil {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(*req.CapeBase64))
			capeReader = &decoder
		}

		updatedUser, err := app.UpdateUser(
			caller,
			profileUser, // user
			req.Password,
			req.IsAdmin,
			req.IsLocked,
			req.PlayerName,
			req.FallbackPlayer,
			req.ResetAPIToken,
			req.PreferredLanguage,
			req.SkinModel,
			skinReader,
			req.SkinURL,
			req.DeleteSkin,
			capeReader,
			req.CapeURL,
			req.DeleteCape,
		)
		if err != nil {
			return err
		}

		apiUser, err := app.userToAPIUser(&updatedUser)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiUser)
	})
}

// TODO DELETE /drasl/api/v1/users/{uuid}

// APIGetInvites godoc
//
//	@Summary		Get invites
//	@Description	Get all invites. Requires admin privileges.
//	@Tags			invites
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIInvite
//	@Failure		403	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/invites [get]
func (app *App) APIGetInvites() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		var invites []Invite
		result := app.DB.Find(&invites)
		if result.Error != nil {
			return result.Error
		}

		apiInvites := make([]APIInvite, 0, len(invites))
		for _, invite := range invites {
			apiInvite, err := app.inviteToAPIInvite(&invite)
			if err != nil {
				return err
			}
			apiInvites = append(apiInvites, apiInvite)
		}

		return c.JSON(http.StatusOK, apiInvites)
	})
}

// APICreateInvite godoc
//
//	@Summary		Create a new invite
//	@Description	Create a new invite with a random code. Requires admin privileges.
//	@Tags			invites
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIInvite
//	@Failure		403	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/invites [post]
func (app *App) APICreateInvite() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		invite, err := app.CreateInvite()
		if err != nil {
			return err
		}
		apiInvite, err := app.inviteToAPIInvite(&invite)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiInvite)
	})
}

// APIDeleteInvite godoc
//
//	@Summary		Delete an invite
//	@Description	Delete an invite invite given its code. Requires admin privileges.
//	@Tags			invites
//	@Accept			json
//	@Produce		json
//	@Success		204
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/invite/{code} [delete]
func (app *App) APIDeleteInvite() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		code := c.Param("code")

		result := app.DB.Where("code = ?", code).Delete(&Invite{})
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "Unknown invite code")
			}
			return result.Error
		}

		return c.NoContent(http.StatusNoContent)
	})
}

// TODO GET /drasl/api/v1/challenge-skin
