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
	Message string `json:"message" example:"An error occurred"`
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

		if user.IsLocked {
			return echo.NewHTTPError(http.StatusForbidden, "Account is locked")
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
	IsAdmin           bool      `json:"isAdmin" example:"true"`   // Whether the user is an admin
	IsLocked          bool      `json:"isLocked" example:"false"` // Whether the user is locked (disabled)
	UUID              string    `json:"uuid" example:"557e0c92-2420-4704-8840-a790ea11551c"`
	Username          string    `json:"username" example:"MyUsername"`                                                                                                       // Username. Can be different from the user's player name.
	PlayerName        string    `json:"playerName" example:"MyPlayerName"`                                                                                                   // Player name, seen by Minecraft. Can be different from the user's username.
	OfflineUUID       string    `json:"offlineUuid" example:"8dcf1aea-9b60-3d88-983b-185671d1a912"`                                                                          // UUID of the user in `online-mode=false` servers. Derived from the user's player name.
	FallbackPlayer    string    `json:"fallbackPlayer" example:"Notch"`                                                                                                      // UUID or player name. If the user doesn't have a skin or cape set, this player's skin on one of the fallback API servers will be used instead.
	PreferredLanguage string    `json:"preferredLanguage" example:"en"`                                                                                                      // One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft.
	SkinURL           *string   `json:"skinUrl" example:"https://drasl.example.com/drasl/texture/skin/fa85a8f3d36beb9b6041b5f50a6b4c33970e281827effc1b22b0f04bcb017331.png"` // URL to the user's skin, if they have set one. If no skin is set, the Minecraft client may still see a skin if `FallbackAPIServers` or default skins are configured.
	SkinModel         string    `json:"skinModel" example:"slim"`                                                                                                            // Skin model. Either `"classic"` or `"slim"`.
	CapeURL           *string   `json:"capeUrl" example:"https://drasl.example.com/drasl/texture/cape/bf74bd4d115c5da69754ebf86b5d33a03dd5ad48910b8c7ebf276bba6b3a5603.png"` // URL to the user's cape, if they have set one. If no cape is set, the Minecraft client may still see a cape if `FallbackAPIServers` or default capes are configured.
	CreatedAt         time.Time `json:"createdAt" example:"2024-05-18T01:11:32.836265485-04:00"`                                                                             // ISO datetime when the user was created
	NameLastChangedAt time.Time `json:"nameLastChangedAt" example:"2024-05-29T13:54:24.448081165-04:00"`                                                                     // ISO 8601 datetime when the user's player name was last changed
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
	Code      string    `json:"code" example:"rqjJwh0yMjO"`                                                    // The base62 invite code
	URL       string    `json:"url" example:"https://drasl.example.com/drasl/registration?invite=rqjJwh0yMjO"` // Link to register using the invite
	CreatedAt time.Time `json:"createdAt" example:"2024-05-18T01:11:32.836265485-04:00"`                       // ISO 8601 datetime when the invite was created
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
//	@Failure		401	{object}	APIError
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
//	@Description	Get details of your own account
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIUser
//	@Failure		403	{object}	APIError
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
//	@Description	Get details of a user by their UUID. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIUser
//	@Failure		400	{object}	APIError
//	@Failure		401	{object}	APIError
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

type APICreateUserRequest struct {
	Username          string  `json:"username" example:"MyUsername"`                                                                     // Username of the new user. Can be different from the user's player name.
	Password          string  `json:"password" example:"hunter2"`                                                                        // Plaintext password
	IsAdmin           bool    `json:"isAdmin" example:"true"`                                                                            // Whether the user is an admin
	IsLocked          bool    `json:"isLocked" example:"false"`                                                                          // Whether the user is locked (disabled)
	ChosenUUID        *string `json:"chosenUuid" example:"557e0c92-2420-4704-8840-a790ea11551c"`                                         // Optional. Specify a UUID for the new user. If omitted, a random UUID will be generated.
	ExistingPlayer    bool    `json:"existingPlayer" example:"false"`                                                                    // If true, the new user will get the UUID of the existing player with the specified PlayerName. See `RegistrationExistingPlayer` in configuration.md.
	InviteCode        *string `json:"inviteCode" example:"rqjJwh0yMjO"`                                                                  // Invite code to use. Optional even if the `RequireInvite` configuration option is set; admin API users can bypass `RequireInvite`.
	PlayerName        *string `json:"playerName" example:"MyPlayerName"`                                                                 // Optional. Player name. Can be different from the user's username. If omitted, the user's username will be used.
	FallbackPlayer    *string `json:"fallbackPlayer" example:"Notch"`                                                                    // Can be a UUID or a player name. If you don't set a skin or cape, this player's skin on one of the fallback API servers will be used instead.
	PreferredLanguage *string `json:"preferredLanguage" example:"en"`                                                                    // Optional. One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft. If omitted, the value of the `DefaultPreferredLanguage` configuration option will be used.
	SkinModel         *string `json:"skinModel" example:"classic"`                                                                       // Skin model. Either "classic" or "slim". If omitted, `"classic"` will be assumed.
	SkinBase64        *string `json:"skinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI"` // Optional. Base64-encoded skin PNG. Example value truncated for brevity. Do not specify both `skinBase64` and `skinUrl`.
	SkinURL           *string `json:"skinUrl" example:"https://example.com/skin.png"`                                                    // Optional. URL to skin file. Do not specify both `skinBase64` and `skinUrl`.
	CapeBase64        *string `json:"capeBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAYAAACinX6EAAABcGlDQ1BpY2MAACiRdZG9S8NAGMaf"` // Optional. Base64-encoded cape PNG. Example value truncated for brevity. Do not specify both `capeBase64` and `capeUrl`.
	CapeURL           *string `json:"capeUrl" example:"https://example.com/cape.png"`                                                    // Optional. URL to cape file. Do not specify both `capeBase64` and `capeUrl`.
}

// Create a user (admin only)
// APIGetUser godoc
//
//	@Summary		Create a new user
//	@Description	Create a new user. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			APICreateUserRequest	body		APICreateUserRequest	true	"Properties of the new user"
//	@Success		200						{object}	APIUser
//	@Failure		401						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v1/users [post]
func (app *App) APICreateUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, caller *User) error {
		req := new(APICreateUserRequest)
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

type APIUpdateUserRequest struct {
	Password          *string `json:"password" example"hunter2"`         // Optional. New plaintext password
	IsAdmin           *bool   `json:"isAdmin" example:"true"`            // Optional. Pass`true` to grant, `false` to revoke admin privileges.
	IsLocked          *bool   `json:"isLocked" example:"false"`          // Optional. Pass `true` to lock (disable), `false` to unlock user.
	PlayerName        *string `json:"playerName" example:"MyPlayerName"` // Optional. New player name. Can be different from the user's username.
	FallbackPlayer    *string `json:"fallbackPlayer" example:"Notch"`    // Optional. New fallback player. Can be a UUID or a player name. If you don't set a skin or cape, this player's skin on one of the fallback API servers will be used instead.
	ResetAPIToken     bool    `json:"resetApiToken" example:"true"`      // Pass `true` to reset the user's API token
	PreferredLanguage *string `json:"preferredLanguage" example:"en"`    // Optional. One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft.
	SkinModel         *string `json:"skinModel" example:"classic"`       // Optional. New skin model. Either "classic" or "slim".
	SkinBase64        *string `json:"skinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI"`
	SkinURL           *string `json:"skinUrl" example:"https://example.com/skin.png"`                                                    // Optional. URL to skin file
	DeleteSkin        bool    `json:"deleteSkin"`                                                                                        // Pass `true` to delete the user's existing skin
	CapeBase64        *string `json:"capeBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAYAAACinX6EAAABcGlDQ1BpY2MAACiRdZG9S8NAGMaf"` // Optional. Base64-encoded cape PNG. Example value truncated for brevity.
	CapeURL           *string `json:"capeUrl" example:"https://example.com/cape.png"`                                                    // Optional. URL to cape file
	DeleteCape        bool    `json:"deleteCape"`                                                                                        // Pass `true` to delete the user's existing cape
}

// APIUpdateUser godoc
//
//	@Summary		Update a user
//	@Description	Update an existing user. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			APIUpdateUserRequest	body		APIUpdateUserRequest	true	"New properties of the user"
//	@Success		200						{object}	APIUser
//	@Failure		400						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		404						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v1/users/{uuid} [patch]
func (app *App) APIUpdateUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, caller *User) error {
		req := new(APIUpdateUserRequest)
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

// APIUpdateSelf godoc
//
//	@Summary		Update own account
//	@Description	Update details of your own account.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			APIUpdateUserRequest	body		APIUpdateUserRequest	true	"New properties of the user"
//	@Success		200						{object}	APIUser
//	@Failure		400						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		404						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v1/user [patch]
func (app *App) APIUpdateSelf() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		req := new(APIUpdateUserRequest)
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

		updatedUser, err := app.UpdateUser(
			user,
			*user,
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

// APIDeleteUser godoc
//
//	@Summary		Delete user
//	@Description	Delete a user. This action cannot be undone. Requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		204
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/users/{uuid} [delete]
func (app *App) APIDeleteUser() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var targetUser User
		result := app.DB.First(&targetUser, "uuid = ?", uuid_)
		if result.Error != nil {
			return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
		}

		err = app.DeleteUser(&targetUser)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}

// APIDeleteSelf godoc
//
//	@Summary		Delete own account
//	@Description	Delete your own account. This action cannot be undone.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		204
//	@Failure		401	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/user [delete]
func (app *App) APIDeleteSelf() func(c echo.Context) error {
	return app.withAPIToken(func(c echo.Context, user *User) error {
		err := app.DeleteUser(user)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}

// APIGetInvites godoc
//
//	@Summary		Get invites
//	@Description	Get details of all invites. Requires admin privileges.
//	@Tags			invites
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		APIInvite
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
//	@Description	Delete an invite given its code. Requires admin privileges.
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

type APIChallenge struct {
	ChallengeSkinBase64 string `json:"challengeSkinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI"` // Base64-encoded skin PNG. Example value truncated for brevity.
	ChallengeToken      string `json:"challengeToken" example:"414cc23d6eebee3b17a453d6b9800be3e5a4627fd3b0ee54d7c37d03b2596e44"`                  // Challenge token that must be passed when registering with a challenge skin
}

// APIGetChallengeSkin godoc
//
//	@Summary		Get a challenge skin/token
//	@Description	Get a challenge skin and challenge token for a username, for registration purposes. See the `RequireSkinVerification` configuration option.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	APIChallenge
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v1/challenge-skin [get]
func (app *App) APIGetChallengeSkin() func(c echo.Context) error {
	return app.withAPIToken(func(c echo.Context, _ *User) error {
		username := c.QueryParam("username")

		challengeToken, err := MakeChallengeToken()
		if err != nil {
			return err
		}

		challengeSkinBytes, err := app.GetChallengeSkin(username, challengeToken)
		if err != nil {
			return err
		}
		challengeSkinBase64 := base64.StdEncoding.EncodeToString(challengeSkinBytes)

		return c.JSON(http.StatusOK, APIChallenge{
			ChallengeSkinBase64: challengeSkinBase64,
			ChallengeToken:      challengeToken,
		})
	})
}
