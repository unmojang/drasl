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

// APIGetUsers godoc
//
//	@Summary		Get users
//	@Description	Get details of all users. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		APIUser
//	@Failure		400	{object}	APIError
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
	Username          string `json:"username"`
	Password          string `json:"password"`
	ChosenUUID        string `json:"chosenUuid,omitempty"`
	ExistingPlayer    bool   `json:"existingPlayer,omitempty"`
	InviteCode        string `json:"inviteCode,omitempty"`
	PlayerName        string `json:"playerName,omitempty"`
	FallbackPlayer    string `json:"fallbackPlayer,omitempty"`
	PreferredLanguage string `json:"preferredLanguage,omitempty"`
	SkinModel         string `json:"skinModel,omitempty"`
	SkinBase64        string `json:"skinBase64,omitempty"`
	SkinURL           string `json:"skinUrl,omitempty"`
	CapeBase64        string `json:"capeBase64,omitempty"`
	CapeURL           string `json:"capeUrl,omitempty"`
}

// POST /drasl/api/v1/users
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
//	@Failure		404					{object}	APIError
//	@Failure		500					{object}	APIError
//	@Router			/drasl/api/v1/users [post]
func (app *App) APICreateUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, caller *User) error {
		req := new(createUserRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		var skinReader *io.Reader
		if req.SkinBase64 != "" {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.SkinBase64))
			skinReader = &decoder
		}

		var capeReader *io.Reader
		if req.CapeBase64 != "" {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(req.CapeBase64))
			capeReader = &decoder
		}

		user, err := app.CreateUser(
			caller,
			req.Username,
			req.Password,
			req.ChosenUUID,
			req.ExistingPlayer,
			"", // challengeToken
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

// PUT /drasl/api/v1/users/{uuid}

// PATCH /drasl/api/v1/users/{uuid}

// DELETE /drasl/api/v1/users/{uuid}

// GET /drasl/api/v1/invites

// POST /drasl/api/v1/invites

// DELETE /drasl/api/v1/invites

// GET /drasl/api/v1/challenge-skin
