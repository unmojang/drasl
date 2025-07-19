package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"gorm.io/gorm"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const API_MAJOR_VERSION = 2

var DRASL_API_PREFIX = fmt.Sprintf("/drasl/api/v%d", API_MAJOR_VERSION)

//	@title			Drasl API
//	@version		2.0
//	@description	Manage Drasl users, players, and invites

//	@contact.name	Unmojang
//	@contact.url	https://github.com/unmojang/drasl

//	@license.name	GPLv3
//	@license.url	https://www.gnu.org/licenses/gpl-3.0.en.html

type APIError struct {
	Message string `json:"message" example:"An error occurred"`
}

func (app *App) HandleAPIError(err error, c *echo.Context) error {
	code := http.StatusInternalServerError
	message := "Internal server error"
	log := true

	if e, ok := err.(*echo.HTTPError); ok {
		code = e.Code

		if m, ok := e.Message.(string); ok {
			message = m
		}

		if code == http.StatusNotFound {
			path_ := (*c).Request().URL.Path
			if version, ok := IsDeprecatedAPIPath(path_).Get(); ok {
				switch version {
				case 1:
					message = "Version 1 of this API was deprecated in release 3.0.0."
				default:
					message = fmt.Sprintf("Version %d of this API is deprecated.", version)
				}
			}
		}

		log = false
	}

	var userError *UserError
	if errors.As(err, &userError) {
		code = userError.Code.OrElse(http.StatusInternalServerError)
		message = userError.Error()
		log = false
	}

	if log {
		LogError(err, c)
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

func IsDeprecatedAPIPath(path_ string) mo.Option[int] {
	if path_ == "/" {
		return mo.None[int]()
	}

	split := strings.Split(path_, "/")
	if len(split) >= 3 && split[1] == "drasl" && split[2] == "api" {
		re := regexp.MustCompile(`v(\d+)`)
		match := re.FindStringSubmatch(split[3])
		if len(match) == 2 {
			version, err := strconv.Atoi(match[1])
			if err == nil && version != API_MAJOR_VERSION {
				return mo.Some(version)
			}
		}
	}

	return mo.None[int]()
}

func (app *App) APIRequestToMaybeUser(c echo.Context) (mo.Option[User], error) {
	authorizationHeader := c.Request().Header.Get("Authorization")
	if authorizationHeader == "" {
		return mo.None[User](), nil
	}

	bearerExp := regexp.MustCompile("^Bearer (.*)$")

	tokenMatch := bearerExp.FindStringSubmatch(authorizationHeader)
	if tokenMatch == nil || len(tokenMatch) < 2 {
		return mo.None[User](), NewUserErrorWithCode(http.StatusUnauthorized, "Malformed Authorization header")
	}
	token := tokenMatch[1]

	var user User
	if err := app.DB.First(&user, "api_token = ?", token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return mo.None[User](), NewUserErrorWithCode(http.StatusUnauthorized, "Unknown API token")
		}
		return mo.None[User](), err
	}

	if user.IsLocked {
		return mo.None[User](), NewUserErrorWithCode(http.StatusForbidden, "Account is locked")
	}

	return mo.Some(user), nil
}

func (app *App) withAPIToken(requireLogin bool, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	return func(c echo.Context) error {
		maybeUser, err := app.APIRequestToMaybeUser(c)
		if err != nil {
			return err
		}
		if maybeUser.IsAbsent() && requireLogin {
			return NewUserErrorWithCode(http.StatusUnauthorized, "Route requires authorization. Missing 'Bearer: abcdef' Authorization header")
		}
		return f(c, maybeUser.ToPointer())
	}
}

func (app *App) withAPITokenAdmin(f func(c echo.Context, user *User) error) func(c echo.Context) error {
	notAnAdminBlob := Unwrap(json.Marshal(map[string]string{
		"error": "You are not an admin.",
	}))
	return app.withAPIToken(true, func(c echo.Context, user *User) error {
		if !user.IsAdmin {
			return c.JSONBlob(http.StatusForbidden, notAnAdminBlob)
		}
		return f(c, user)
	})
}

type APIUser struct {
	IsAdmin           bool              `json:"isAdmin" example:"true"`   // Whether the user is an admin
	IsLocked          bool              `json:"isLocked" example:"false"` // Whether the user is locked (disabled)
	UUID              string            `json:"uuid" example:"557e0c92-2420-4704-8840-a790ea11551c"`
	Username          string            `json:"username" example:"MyUsername"`  // Username. Can be different from the user's player name.
	PreferredLanguage string            `json:"preferredLanguage" example:"en"` // One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft.
	MaxPlayerCount    int               `json:"maxPlayerCount" example:"3"`     // Maximum number of players a user is allowed to own. -1 means unlimited players. -2 means use the default configured value.
	Players           []APIPlayer       `json:"players"`                        // A user can have multiple players.
	OIDCIdentities    []APIOIDCIdentity `json:"oidcIdentities"`                 // OIDC identities linked to the user
}

func (app *App) userToAPIUser(user *User) (APIUser, error) {
	apiPlayers := make([]APIPlayer, 0, len(user.Players))
	for _, player := range user.Players {
		apiPlayer, err := app.playerToAPIPlayer(&player)
		if err != nil {
			return APIUser{}, err
		}
		apiPlayers = append(apiPlayers, apiPlayer)
	}

	apiOIDCIdentities := make([]APIOIDCIdentity, 0, len(user.OIDCIdentities))
	for _, oidcIdentity := range user.OIDCIdentities {
		apiOIDCIdentity, err := app.oidcIdentityToAPIOIDCIdentity(&oidcIdentity)
		if err != nil {
			return APIUser{}, err
		}
		apiOIDCIdentities = append(apiOIDCIdentities, apiOIDCIdentity)
	}

	return APIUser{
		IsAdmin:           user.IsAdmin,
		IsLocked:          user.IsLocked,
		UUID:              user.UUID,
		Username:          user.Username,
		PreferredLanguage: user.PreferredLanguage,
		Players:           apiPlayers,
		OIDCIdentities:    apiOIDCIdentities,
		MaxPlayerCount:    user.MaxPlayerCount,
	}, nil
}

type APIPlayer struct {
	UserUUID          string    `json:"userUuid" example:"918bd04e-1bc4-4ccd-860f-60c15c5f1cec"`                                                                             // UUID of the owning user.
	Name              string    `json:"name" example:"MyPlayerName"`                                                                                                         // Player name, seen by Minecraft. Can be different from the owning user's username.
	UUID              string    `json:"uuid" example:"e6d266d5-d559-4ec4-bc9b-1866d13d7f91"`                                                                                 // UUID of the player, seen by Minecraft. Not guaranteed to be different from the owning user's UUID.
	OfflineUUID       string    `json:"offlineUuid" example:"8dcf1aea-9b60-3d88-983b-185671d1a912"`                                                                          // UUID of the user in `online-mode=false` servers. Derived from the user's player name.
	FallbackPlayer    string    `json:"fallbackPlayer" example:"Notch"`                                                                                                      // UUID or player name. If the user doesn't have a skin or cape set, this player's skin on one of the fallback API servers will be used instead.
	SkinModel         string    `json:"skinModel" example:"slim"`                                                                                                            // Skin model. Either `"classic"` or `"slim"`.
	SkinURL           *string   `json:"skinUrl" example:"https://drasl.example.com/drasl/texture/skin/fa85a8f3d36beb9b6041b5f50a6b4c33970e281827effc1b22b0f04bcb017331.png"` // URL to the user's skin, if they have set one. If no skin is set, the Minecraft client may still see a skin if `FallbackAPIServers` or default skins are configured.
	CapeURL           *string   `json:"capeUrl" example:"https://drasl.example.com/drasl/texture/cape/bf74bd4d115c5da69754ebf86b5d33a03dd5ad48910b8c7ebf276bba6b3a5603.png"` // URL to the user's cape, if they have set one. If no cape is set, the Minecraft client may still see a cape if `FallbackAPIServers` or default capes are configured.
	CreatedAt         time.Time `json:"createdAt" example:"2024-05-18T01:11:32.836265485-04:00"`                                                                             // ISO datetime when the user was created
	NameLastChangedAt time.Time `json:"nameLastChangedAt" example:"2024-05-29T13:54:24.448081165-04:00"`                                                                     // ISO 8601 datetime when the user's player name was last changed
}

func (app *App) playerToAPIPlayer(player *Player) (APIPlayer, error) {
	skinURL, err := app.GetSkinURL(player)
	if err != nil {
		return APIPlayer{}, err
	}
	capeURL, err := app.GetCapeURL(player)
	if err != nil {
		return APIPlayer{}, err
	}
	return APIPlayer{
		UserUUID:          player.UserUUID,
		Name:              player.Name,
		UUID:              player.UUID,
		OfflineUUID:       player.OfflineUUID,
		FallbackPlayer:    player.FallbackPlayer,
		SkinURL:           skinURL,
		SkinModel:         player.SkinModel,
		CapeURL:           capeURL,
		CreatedAt:         player.CreatedAt,
		NameLastChangedAt: player.NameLastChangedAt,
	}, nil
}

type APIOIDCIdentity struct {
	UserUUID         string `json:"userUuid" example:"918bd04e-1bc4-4ccd-860f-60c15c5f1cec"`
	OIDCProviderName string `json:"oidcProviderName" example:"Kanidm"`
	Issuer           string `json:"issuer" example:"https://idm.example.com/oauth2/openid/drasl"`
	Subject          string `json:"subject" example:"f85f8c18-9bdf-49ad-a76e-719f9ba3ed25"`
}

func (app *App) oidcIdentityToAPIOIDCIdentity(oidcIdentity *UserOIDCIdentity) (APIOIDCIdentity, error) {
	oidcProvider, ok := app.OIDCProvidersByIssuer[oidcIdentity.Issuer]
	if !ok {
		return APIOIDCIdentity{}, InternalServerError
	}
	return APIOIDCIdentity{
		UserUUID:         oidcIdentity.UserUUID,
		OIDCProviderName: oidcProvider.Config.Name,
		Issuer:           oidcIdentity.Issuer,
		Subject:          oidcIdentity.Subject,
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

func (app *App) APISwagger() func(c echo.Context) error {
	swaggerPath := path.Join(app.Config.DataDirectory, "assets", "swagger.json")
	swaggerBlob := Unwrap(os.ReadFile(swaggerPath))
	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, swaggerBlob)
	}
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
//	@Router			/drasl/api/v2/users [get]
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

// APIGetUser godoc
//
//	@Summary		Get user details
//	@Description	Get details of a user, either the calling user (GET /user) or the user with the specified UUID (GET /users/{uuid}). Getting details of another user requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			uuid	path		string	true	"User UUID"
//	@Success		200		{object}	APIUser
//	@Failure		400		{object}	APIError
//	@Failure		401		{object}	APIError
//	@Failure		403		{object}	APIError
//	@Failure		404		{object}	APIError
//	@Failure		500		{object}	APIError
//	@Router			/drasl/api/v2/users/{uuid} [get]
//	@Router			/drasl/api/v2/user [get]
func (app *App) APIGetUser() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		targetUser := caller

		uuidParam := c.Param("uuid")
		if uuidParam != "" {
			if !caller.IsAdmin && (caller.UUID != uuidParam) {
				return NewUserErrorWithCode(http.StatusForbidden, "You are not authorized to access that user.")
			}

			_, err := uuid.Parse(uuidParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
			}

			var targetUserStruct User
			if err := app.DB.First(&targetUserStruct, "uuid = ?", uuidParam).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
				}
				return err
			}

			targetUser = &targetUserStruct
		}

		apiUser, err := app.userToAPIUser(targetUser)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiUser)
	})
}

type APIOIDCIdentitySpec struct {
	Issuer  string `json:"issuer" example:"https://idm.example.com/oauth2/openid/drasl"`
	Subject string `json:"subject" example:"f85f8c18-9bdf-49ad-a76e-719f9ba3ed25"`
}

type APICreateUserRequest struct {
	Username          string                `json:"username" example:"MyUsername"` // Username of the new user. Can be different from the user's player name.
	Password          *string               `json:"password" example:"hunter2"`    // Plaintext password. Not needed if OIDCIdentitySpecs are supplied.
	OIDCIdentitySpecs []APIOIDCIdentitySpec `json:"oidcIdentities"`
	IsAdmin           bool                  `json:"isAdmin" example:"true"`                                                                               // Whether the user is an admin
	IsLocked          bool                  `json:"isLocked" example:"false"`                                                                             // Whether the user is locked (disabled)
	RequestAPIToken   bool                  `json:"requestApiToken" example:"true"`                                                                       // Whether to include an API token for the user in the response
	ChosenUUID        *string               `json:"chosenUuid" example:"557e0c92-2420-4704-8840-a790ea11551c"`                                            // Optional. Specify a UUID for the player of the new user. If omitted, a random UUID will be generated.
	ExistingPlayer    bool                  `json:"existingPlayer" example:"false"`                                                                       // If true, the new user's player will get the UUID of the existing player with the specified PlayerName. See `RegistrationExistingPlayer` in configuration.md.
	InviteCode        *string               `json:"inviteCode" example:"rqjJwh0yMjO"`                                                                     // Invite code to use. Optional even if the `RequireInvite` configuration option is set; admin API users can bypass `RequireInvite`.
	PlayerName        *string               `json:"playerName" example:"MyPlayerName"`                                                                    // Optional. Player name. Can be different from the user's username. If omitted, the user's username will be used.
	FallbackPlayer    *string               `json:"fallbackPlayer" example:"Notch"`                                                                       // Can be a UUID or a player name. If you don't set a skin or cape, this player's skin on one of the fallback API servers will be used instead.
	PreferredLanguage *string               `json:"preferredLanguage" example:"en"`                                                                       // Optional. One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft. If omitted, the value of the `DefaultPreferredLanguage` configuration option will be used.
	SkinModel         *string               `json:"skinModel" example:"classic"`                                                                          // Skin model. Either "classic" or "slim". If omitted, `"classic"` will be assumed.
	SkinBase64        *string               `json:"skinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI..."` // Optional. Base64-encoded skin PNG. Example value truncated for brevity. Do not specify both `skinBase64` and `skinUrl`.
	SkinURL           *string               `json:"skinUrl" example:"https://example.com/skin.png"`                                                       // Optional. URL to skin file. Do not specify both `skinBase64` and `skinUrl`.
	CapeBase64        *string               `json:"capeBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAYAAACinX6EAAABcGlDQ1BpY2MAACiRdZG9S8NAGMaf..."` // Optional. Base64-encoded cape PNG. Example value truncated for brevity. Do not specify both `capeBase64` and `capeUrl`.
	CapeURL           *string               `json:"capeUrl" example:"https://example.com/cape.png"`                                                       // Optional. URL to cape file. Do not specify both `capeBase64` and `capeUrl`.
	MaxPlayerCount    *int                  `json:"maxPlayerCount" example:"3"`                                                                           // Optional. Maximum number of players a user is allowed to own. -1 means unlimited players. -2 means use the default configured value.
}

type APICreateUserResponse struct {
	User     APIUser `json:"user"`                                                // The new user.
	APIToken *string `json:"apiToken,omitempty" example:"Bq608AtLeG7emJOdvXHYxL"` // An API token for the new user, if requested.
}

// APICreateUser godoc
//
//	@Summary		Create a new user
//	@Description	Register and create a new user. Can be called without an API token.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			APICreateUserRequest	body		APICreateUserRequest	true	"Properties of the new user"
//	@Success		200						{object}	APICreateUserResponse
//	@Failure		400						{object}	APIError
//	@Failure		401						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		429						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v2/users [post]
func (app *App) APICreateUser() func(c echo.Context) error {
	return app.withAPIToken(false, func(c echo.Context, caller *User) error {
		callerIsAdmin := caller != nil && caller.IsAdmin

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

		if !callerIsAdmin && len(req.OIDCIdentitySpecs) > 0 {
			return NewBadRequestUserError("Can't create a user with OIDC identities without admin privileges.")
		}
		oidcIdentitySpecs := make([]OIDCIdentitySpec, 0, len(req.OIDCIdentitySpecs))
		for _, ois := range req.OIDCIdentitySpecs {
			oidcIdentitySpecs = append(oidcIdentitySpecs, OIDCIdentitySpec(ois))
		}

		user, err := app.CreateUser(
			caller,
			req.Username,
			req.Password,
			PotentiallyInsecure[[]OIDCIdentitySpec]{Value: oidcIdentitySpecs},
			req.IsAdmin,
			req.IsLocked,
			req.InviteCode,
			req.PreferredLanguage,
			req.PlayerName,
			req.ChosenUUID,
			req.ExistingPlayer,
			nil, // challengeToken
			req.FallbackPlayer,
			req.MaxPlayerCount,
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
		var response APICreateUserResponse
		response.User = apiUser
		if req.RequestAPIToken {
			response.APIToken = &user.APIToken
		}
		return c.JSON(http.StatusOK, response)
	})
}

type APIUpdateUserRequest struct {
	Password            *string `json:"password" example:"hunter2"`          // Optional. New plaintext password
	IsAdmin             *bool   `json:"isAdmin" example:"true"`              // Optional. Pass`true` to grant, `false` to revoke admin privileges.
	IsLocked            *bool   `json:"isLocked" example:"false"`            // Optional. Pass `true` to lock (disable), `false` to unlock user.
	ResetAPIToken       bool    `json:"resetApiToken" example:"false"`       // Pass `true` to reset the user's API token
	ResetMinecraftToken bool    `json:"resetMinecraftToken" example:"false"` // Pass `true` to reset the user's Minecraft token
	PreferredLanguage   *string `json:"preferredLanguage" example:"en"`      // Optional. One of the two-letter codes in https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html. Used by Minecraft.
	MaxPlayerCount      *int    `json:"maxPlayerCount" example:"3"`          // Optional. Maximum number of players a user is allowed to own. -1 means unlimited players. -2 means use the default configured value.
}

// APIUpdateUser godoc
//
//	@Summary		Update a user
//	@Description	Update an existing user, either the calling user (PATCH /user) or the user with the specified UUID (PATCH /users/{uuid}). Updating another user requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			uuid					path		string					true	"User UUID"
//	@Param			APIUpdateUserRequest	body		APIUpdateUserRequest	true	"New properties of the user"
//	@Success		200						{object}	APIUser
//	@Failure		400						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		404						{object}	APIError
//	@Failure		429						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v2/users/{uuid} [patch]
//	@Router			/drasl/api/v2/user [patch]
func (app *App) APIUpdateUser() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		req := new(APIUpdateUserRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		targetUser := caller
		uuidParam := c.Param("uuid")
		if uuidParam != "" {
			if !caller.IsAdmin && (caller.UUID != uuidParam) {
				return NewUserErrorWithCode(http.StatusForbidden, "You are not authorized to update that user.")
			}

			_, err := uuid.Parse(uuidParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
			}

			var targetUserStruct User
			if err := app.DB.First(&targetUserStruct, "uuid = ?", uuidParam).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
				}
				return err
			}

			targetUser = &targetUserStruct
		}

		updatedUser, err := app.UpdateUser(
			app.DB,
			caller,
			*targetUser,
			req.Password,
			req.IsAdmin,
			req.IsLocked,
			req.ResetAPIToken,
			req.ResetMinecraftToken,
			req.PreferredLanguage,
			req.MaxPlayerCount,
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
//	@Description	Delete a user, either the calling user (DELETE /user) or the user with the specified UUID (DELETE /users/{uuid}). This action cannot be undone. Deleting another user requires admin privileges.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			uuid	path	string	true	"User UUID"
//	@Success		204
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v2/user [delete]
//	@Router			/drasl/api/v2/users/{uuid} [delete]
func (app *App) APIDeleteUser() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		targetUser := caller
		uuidParam := c.Param("uuid")
		if uuidParam != "" {
			if !caller.IsAdmin && (caller.UUID != uuidParam) {
				return NewUserErrorWithCode(http.StatusForbidden, "You are not authorized to update that user.")
			}

			_, err := uuid.Parse(uuidParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
			}

			var targetUserStruct User
			if err := app.DB.First(&targetUserStruct, "uuid = ?", uuidParam).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return echo.NewHTTPError(http.StatusNotFound, "Unknown UUID")
				}
				return err
			}

			targetUser = &targetUserStruct
		}

		err := app.DeleteUser(caller, targetUser)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}

// APIGetPlayer godoc
//
//	@Summary		Get player by UUID
//	@Description	Get details of a player by their UUID. Requires admin privileges unless you own the player.
//	@Tags			players
//	@Accept			json
//	@Produce		json
//	@Param			uuid	path		string	true	"Player UUID"
//	@Success		200		{object}	APIPlayer
//	@Failure		400		{object}	APIError
//	@Failure		401		{object}	APIError
//	@Failure		403		{object}	APIError
//	@Failure		404		{object}	APIError
//	@Failure		500		{object}	APIError
//	@Router			/drasl/api/v2/players/{uuid} [get]
func (app *App) APIGetPlayer() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, user *User) error {
		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var player Player
		result := app.DB.Preload("User").First(&player, "uuid = ?", uuid_)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "Player not found.")
			}
			return result.Error
		}
		if !user.IsAdmin && (player.User.UUID != user.UUID) {
			return echo.NewHTTPError(http.StatusForbidden, "You don't own that player.")
		}

		apiPlayer, err := app.playerToAPIPlayer(&player)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiPlayer)
	})
}

// APIGetPlayers godoc
//
//	@Summary		Get players
//	@Description	Get details of all players. Requires admin privileges.
//	@Tags			players
//	@Accept			json
//	@Produce		json
//	@Success		200	{array}		APIPlayer
//	@Failure		401	{object}	APIError
//	@Failure		403	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v2/players [get]
func (app *App) APIGetPlayers() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		var players []Player
		result := app.DB.Find(&players)
		if result.Error != nil {
			return result.Error
		}

		apiPlayers := make([]APIPlayer, 0, len(players))
		for _, player := range players {
			apiPlayer, err := app.playerToAPIPlayer(&player)
			if err != nil {
				return err
			}
			apiPlayers = append(apiPlayers, apiPlayer)
		}

		return c.JSON(http.StatusOK, apiPlayers)
	})
}

type APICreatePlayerRequest struct {
	Name           string  `json:"name" example:"MyPlayerName"`                                                                          // Player name.
	UserUUID       *string `json:"userUuid" example:"f9b9af62-da83-4ec7-aeea-de48c621822c"`                                              // Optional. UUID of the owning user. If omitted, the player will be added to the calling user's account.
	ChosenUUID     *string `json:"chosenUuid" example:"557e0c92-2420-4704-8840-a790ea11551c"`                                            // Optional. Specify a UUID for the new player. If omitted, a random UUID will be generated.
	ExistingPlayer bool    `json:"existingPlayer" example:"false"`                                                                       // If true, the new player will get the UUID of the existing player with the specified PlayerName. See `RegistrationExistingPlayer` in configuration.md.
	FallbackPlayer *string `json:"fallbackPlayer" example:"Notch"`                                                                       // Can be a UUID or a player name. If you don't set a skin or cape, this player's skin on one of the fallback API servers will be used instead.
	ChallengeToken *string `json:"challengeToken" example:"iK1B2FzLc5fMP94VmUR3KC"`                                                      // Challenge token to use when verifying ownership of another player. Call /drasl/api/v2/challenge-skin first to get a skin and token. See `RequireSkinVerification` in configuration.md.
	SkinModel      *string `json:"skinModel" example:"classic"`                                                                          // Skin model. Either "classic" or "slim". If omitted, `"classic"` will be assumed.
	SkinBase64     *string `json:"skinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI..."` // Optional. Base64-encoded skin PNG. Example value truncated for brevity. Do not specify both `skinBase64` and `skinUrl`.
	SkinURL        *string `json:"skinUrl" example:"https://example.com/skin.png"`                                                       // Optional. URL to skin file. Do not specify both `skinBase64` and `skinUrl`.
	CapeBase64     *string `json:"capeBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAYAAACinX6EAAABcGlDQ1BpY2MAACiRdZG9S8NAGMaf..."` // Optional. Base64-encoded cape PNG. Example value truncated for brevity. Do not specify both `capeBase64` and `capeUrl`.
	CapeURL        *string `json:"capeUrl" example:"https://example.com/cape.png"`                                                       // Optional. URL to cape file. Do not specify both `capeBase64` and `capeUrl`.
}

// APICreatePlayer godoc
//
//	@Summary		Create a new player
//	@Description	Create a new player for an existing Drasl user.
//	@Tags			players
//	@Accept			json
//	@Produce		json
//	@Param			APICreatePlayerRequest	body		APICreatePlayerRequest	true	"Properties of the new player"
//	@Success		200						{object}	APIPlayer
//	@Failure		400						{object}	APIError
//	@Failure		401						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v2/players [post]
func (app *App) APICreatePlayer() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		req := new(APICreatePlayerRequest)
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

		userUUID := caller.UUID
		if req.UserUUID != nil {
			userUUID = *req.UserUUID
		}

		player, err := app.CreatePlayer(
			caller,
			userUUID,
			req.Name,
			req.ChosenUUID,
			req.ExistingPlayer,
			req.ChallengeToken,
			req.FallbackPlayer,
			req.SkinModel,
			skinReader,
			req.SkinURL,
			capeReader,
			req.CapeURL,
		)

		if err != nil {
			return err
		}

		apiPlayer, err := app.playerToAPIPlayer(&player)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiPlayer)
	})
}

type APIUpdatePlayerRequest struct {
	Name           *string `json:"name" example:"MyPlayerName"`                                                                          // Optional. New player name. Can be different from the user's username.
	FallbackPlayer *string `json:"fallbackPlayer" example:"Notch"`                                                                       // Optional. New fallback player. Can be a UUID or a player name. If you don't set a skin or cape, this player's skin on one of the fallback API servers will be used instead.
	SkinModel      *string `json:"skinModel" example:"classic"`                                                                          // Optional. New skin model. Either "classic" or "slim".
	SkinBase64     *string `json:"skinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI..."` // Optional. Base64-encoded skin PNG. Example value truncated for brevity.
	SkinURL        *string `json:"skinUrl" example:"https://example.com/skin.png"`                                                       // Optional. URL to skin file
	DeleteSkin     bool    `json:"deleteSkin"`                                                                                           // Pass `true` to delete the user's existing skin
	CapeBase64     *string `json:"capeBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAYAAACinX6EAAABcGlDQ1BpY2MAACiRdZG9S8NAGMaf..."` // Optional. Base64-encoded cape PNG. Example value truncated for brevity.
	CapeURL        *string `json:"capeUrl" example:"https://example.com/cape.png"`                                                       // Optional. URL to cape file
	DeleteCape     bool    `json:"deleteCape"`                                                                                           // Pass `true` to delete the user's existing cape
}

// APIUpdatePlayer godoc
//
//	@Summary		Update a player
//	@Description	Update an existing player. Requires admin privileges unless you own the player.
//	@Tags			players
//	@Accept			json
//	@Produce		json
//	@Param			uuid					path		string					true	"Player UUID"
//	@Param			APIUpdatePlayerRequest	body		APIUpdatePlayerRequest	true	"New properties of the player"
//	@Success		200						{object}	APIUser
//	@Failure		400						{object}	APIError
//	@Failure		403						{object}	APIError
//	@Failure		404						{object}	APIError
//	@Failure		429						{object}	APIError
//	@Failure		500						{object}	APIError
//	@Router			/drasl/api/v2/players/{uuid} [patch]
func (app *App) APIUpdatePlayer() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		req := new(APIUpdatePlayerRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var player Player
		if err := app.DB.First(&player, "uuid = ?", uuid_).Error; err != nil {
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

		updatedPlayer, err := app.UpdatePlayer(
			caller,
			player,
			req.Name,
			req.FallbackPlayer,
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

		apiPlayer, err := app.playerToAPIPlayer(&updatedPlayer)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiPlayer)
	})
}

// APIDeletePlayer godoc
//
//	@Summary		Delete player
//	@Description	Delete a player. This action cannot be undone. Requires admin privileges unless you own the player.
//	@Tags			players
//	@Accept			json
//	@Produce		json
//	@Param			uuid	path	string	true	"Player UUID"
//	@Success		204
//	@Failure		401	{object}	APIError
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v2/players/{uuid} [delete]
func (app *App) APIDeletePlayer() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, user *User) error {
		uuid_ := c.Param("uuid")
		_, err := uuid.Parse(uuid_)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
		}

		var player Player
		result := app.DB.First(&player, "uuid = ?", uuid_)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "Player not found.")
			}
			return err
		}
		err = app.DeletePlayer(user, &player)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}

type APICreateOIDCIdentityRequest struct {
	Issuer  string `json:"issuer" example:"https://idm.example.com/oauth2/openid/drasl"`
	Subject string `json:"subject" example:"f85f8c18-9bdf-49ad-a76e-719f9ba3ed25"`
}

// APICreateOIDCIdentity godoc
//
//	@Summary	Link an OIDC identity to a user
//	@Tags		users
//	@Accept		json
//	@Produce	json
//	@Param		uuid							path		string							true	"User UUID"
//	@Param		APICreateOIDCIdentityRequest	body		APICreateOIDCIdentityRequest	true	"OIDC identity to link to the user"
//	@Success	200								{object}	APIOIDCIdentity
//	@Failure	400								{object}	APIError
//	@Failure	401								{object}	APIError
//	@Failure	403								{object}	APIError
//	@Failure	404								{object}	APIError
//	@Failure	500								{object}	APIError
//	@Router		/drasl/api/v2/user/oidc-identities [post]
//	@Router		/drasl/api/v2/users/{uuid}/oidc-identities [post]
func (app *App) APICreateOIDCIdentity() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		req := new(APICreateOIDCIdentityRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		userUUID := caller.UUID
		uuidParam := c.Param("uuid")
		if uuidParam != "" {
			_, err := uuid.Parse(uuidParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
			}
			userUUID = uuidParam
		}

		oidcIdentity, err := app.CreateOIDCIdentity(caller, userUUID, req.Issuer, req.Subject)
		if err != nil {
			return err
		}

		apiOIDCIdentity, err := app.oidcIdentityToAPIOIDCIdentity(&oidcIdentity)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, apiOIDCIdentity)
	})
}

type APIDeleteOIDCIdentityRequest struct {
	Issuer string `json:"issuer" example:"https://idm.example.com/oauth2/openid/drasl"`
}

// APIDeleteOIDCIdentity godoc
//
//	@Summary	Unlink an OIDC identity from a user
//	@Tags		users
//	@Accept		json
//	@Produce	json
//	@Param		uuid							path	string							true	"User UUID"
//	@Param		APIDeleteOIDCIdentityRequest	body	APIDeleteOIDCIdentityRequest	true	"Issuer of the OIDC provider to unlink from the user"
//	@Success	204
//	@Failure	400	{object}	APIError
//	@Failure	401	{object}	APIError
//	@Failure	403	{object}	APIError
//	@Failure	404	{object}	APIError
//	@Failure	500	{object}	APIError
//	@Router		/drasl/api/v2/user/oidc-identities [delete]
//	@Router		/drasl/api/v2/users/{uuid}/oidc-identities [delete]
func (app *App) APIDeleteOIDCIdentity() func(c echo.Context) error {
	return app.withAPIToken(true, func(c echo.Context, caller *User) error {
		req := new(APIDeleteOIDCIdentityRequest)
		if err := c.Bind(req); err != nil {
			return err
		}

		userUUID := caller.UUID
		uuidParam := c.Param("uuid")
		if uuidParam != "" {
			_, err := uuid.Parse(uuidParam)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid UUID")
			}
			userUUID = uuidParam
		}

		oidcProvider, ok := app.OIDCProvidersByIssuer[req.Issuer]
		if !ok {
			return NewBadRequestUserError("Unknown OIDC provider: %s", req.Issuer)
		}

		err := app.DeleteOIDCIdentity(caller, userUUID, oidcProvider.Config.Name)
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
//	@Router			/drasl/api/v2/invites [get]
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
//	@Router			/drasl/api/v2/invites [post]
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
//	@Param			code	path	string	true	"Invite code"
//	@Success		204
//	@Failure		403	{object}	APIError
//	@Failure		404	{object}	APIError
//	@Failure		500	{object}	APIError
//	@Router			/drasl/api/v2/invites/{code} [delete]
func (app *App) APIDeleteInvite() func(c echo.Context) error {
	return app.withAPITokenAdmin(func(c echo.Context, user *User) error {
		code := c.Param("code")

		result := app.DB.Where("code = ?", code).Delete(&Invite{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return NewUserErrorWithCode(http.StatusNotFound, "Unknown invite code")
		}

		return c.NoContent(http.StatusNoContent)
	})
}

type APIGetChallengeSkinRequest struct {
	PlayerName string `json:"playerName" example:"Notch"`
}

type APIChallenge struct {
	ChallengeSkinBase64 string `json:"challengeSkinBase64" example:"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgI..."` // Base64-encoded skin PNG. Example value truncated for brevity.
	ChallengeToken      string `json:"challengeToken" example:"iK1B2FzLc5fMP94VmUR3KC"`                                                               // Challenge token that must be passed when registering with a challenge skin
}

// APIGetChallengeSkin godoc
//
//	@Summary		Get a challenge skin/token
//	@Description	Get a challenge skin and challenge token for a player name for registration or player creation purposes. See the `ImportExistingPlayer.RequireSkinVerification` configuration option.
//	@Tags			users, players
//	@Accept			json
//	@Produce		json
//	@Param			APIGetChallengeSkinRequest	body		APIGetChallengeSkinRequest	true	"Player name for the challenge skin"
//	@Success		200							{object}	APIChallenge
//	@Success		400							{object}	APIError
//	@Failure		500							{object}	APIError
//	@Router			/drasl/api/v2/challenge-skin [get]
func (app *App) APIGetChallengeSkin() func(c echo.Context) error {
	return app.withAPIToken(false, func(c echo.Context, _ *User) error {
		req := new(APIGetChallengeSkinRequest)
		if err := c.Bind(req); err != nil {
			return err
		}
		playerName := req.PlayerName

		challengeToken, err := MakeChallengeToken()
		if err != nil {
			return err
		}

		challengeSkinBytes, err := app.GetChallengeSkin(playerName, challengeToken)
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

type APILoginResponse struct {
	User     APIUser `json:"user"`                                      // The logged-in user
	APIToken string  `json:"apiToken" example:"Bq608AtLeG7emJOdvXHYxL"` // An API token for the user
}

type APILoginRequest struct {
	Username string `json:"username" example:"Notch"`
	Password string `json:"password" example:"hunter2"`
}

// APILogin godoc
//
//	@Summary		Authenticate and receive an API token
//	@Description	Authenticate with username and password and receive an API token. Can be called without an API token.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			APILoginRequest	body		APILoginRequest	true	"Drasl username and password"
//	@Success		200				{object}	APILoginResponse
//	@Failure		400				{object}	APIError
//	@Failure		401				{object}	APIError
//	@Failure		403				{object}	APIError
//	@Failure		429				{object}	APIError
//	@Failure		500				{object}	APIError
//	@Router			/drasl/api/v2/login [post]
func (app *App) APILogin() func(c echo.Context) error {
	return app.withAPIToken(false, func(c echo.Context, _ *User) error {
		var req APILoginRequest
		err := c.Bind(&req)
		if err != nil {
			return err
		}

		user, err := app.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			return err
		}

		apiUser, err := app.userToAPIUser(&user)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, APILoginResponse{User: apiUser, APIToken: user.APIToken})
	})
}
