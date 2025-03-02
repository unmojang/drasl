package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"gorm.io/gorm"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

/*
Web front end for creating user accounts, changing passwords, skins, player names, etc.
*/

const BROWSER_TOKEN_AGE_SEC = 24 * 60 * 60
const COOKIE_PREFIX = "__Host-"
const BROWSER_TOKEN_COOKIE_NAME = COOKIE_PREFIX + "browserToken"
const SUCCESS_MESSAGE_COOKIE_NAME = COOKIE_PREFIX + "successMessage"
const WARNING_MESSAGE_COOKIE_NAME = COOKIE_PREFIX + "warningMessage"
const ERROR_MESSAGE_COOKIE_NAME = COOKIE_PREFIX + "errorMessage"
const OIDC_STATE_COOKIE_NAME = COOKIE_PREFIX + "state"
const ID_TOKEN_COOKIE_NAME = COOKIE_PREFIX + "idToken"
const CHALLENGE_TOKEN_COOKIE_NAME = COOKIE_PREFIX + "challengeToken"

// https://echo.labstack.com/guide/templates/
// https://stackoverflow.com/questions/36617949/how-to-use-base-template-file-for-golang-html-template/69244593#69244593
type Template struct {
	Templates map[string]*template.Template
}

func NewTemplate(app *App) *Template {
	t := &Template{
		Templates: make(map[string]*template.Template),
	}

	templateDir := path.Join(app.Config.DataDirectory, "view")

	names := []string{
		"root",
		"user",
		"player",
		"registration",
		"complete-registration",
		"challenge",
		"admin",
	}

	funcMap := template.FuncMap{
		"PlayerSkinURL":  app.PlayerSkinURL,
		"InviteURL":      app.InviteURL,
		"IsDefaultAdmin": app.IsDefaultAdmin,
	}

	for _, name := range names {
		tmpl := Unwrap(template.New("").Funcs(funcMap).ParseFiles(
			path.Join(templateDir, "layout.tmpl"),
			path.Join(templateDir, name+".tmpl"),
			path.Join(templateDir, "header.tmpl"),
			path.Join(templateDir, "footer.tmpl"),
		))
		t.Templates[name] = tmpl
	}

	return t
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.Templates[name].ExecuteTemplate(w, "base", data)
}

func (app *App) setMessageCookie(c *echo.Context, cookieName string, template string, args ...interface{}) {
	message := fmt.Sprintf(template, args...)
	(*c).SetCookie(&http.Cookie{
		Name:     cookieName,
		Value:    url.QueryEscape(message),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   true,
	})
}

func (app *App) setSuccessMessage(c *echo.Context, template string, args ...interface{}) {
	app.setMessageCookie(c, SUCCESS_MESSAGE_COOKIE_NAME, template, args...)
}

func (app *App) setWarningMessage(c *echo.Context, template string, args ...interface{}) {
	app.setMessageCookie(c, WARNING_MESSAGE_COOKIE_NAME, template, args...)
}

func (app *App) setErrorMessage(c *echo.Context, template string, args ...interface{}) {
	app.setMessageCookie(c, ERROR_MESSAGE_COOKIE_NAME, template, args...)
}

func (app *App) setBrowserToken(c *echo.Context, browserToken string) {
	(*c).SetCookie(&http.Cookie{
		Name:     BROWSER_TOKEN_COOKIE_NAME,
		Value:    browserToken,
		MaxAge:   BROWSER_TOKEN_AGE_SEC,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   true,
	})
}

func (e *WebError) Error() string {
	return e.Err.Error()
}

type WebError struct {
	Err       error
	ReturnURL string
}

func NewWebError(returnURL string, message string, args ...interface{}) error {
	return &WebError{
		Err:       fmt.Errorf(message, args...),
		ReturnURL: returnURL,
	}
}

// Set error message and redirect
func (app *App) HandleWebError(err error, c *echo.Context) error {
	var webError *WebError
	var userError *UserError
	if errors.As(err, &webError) {
		returnURL := webError.ReturnURL
		app.setErrorMessage(c, webError.Error())
		return (*c).Redirect(http.StatusSeeOther, returnURL)
	} else if errors.As(err, &userError) {
		returnURL := getReturnURL(app, c)
		app.setErrorMessage(c, userError.Error())
		return (*c).Redirect(http.StatusSeeOther, returnURL)
	} else if httpError, ok := err.(*echo.HTTPError); ok {
		switch httpError.Code {
		// TODO should probably show a proper 404 Not Found page instead of
		// setting error message and redirecting
		case http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
			if message, ok := httpError.Message.(string); ok {
				returnURL := getReturnURL(app, c)
				app.setErrorMessage(c, message)
				return (*c).Redirect(http.StatusSeeOther, returnURL)
			}
		}
	}
	app.LogError(err, c)
	returnURL := getReturnURL(app, c)
	app.setErrorMessage(c, "Internal server error")
	return (*c).Redirect(http.StatusSeeOther, returnURL)
}

// Read and clear the message cookie
func (app *App) lastMessageCookie(c *echo.Context, cookieName string) string {
	cookie, err := (*c).Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	app.setMessageCookie(c, cookieName, "")
	return decoded
}

func (app *App) lastSuccessMessage(c *echo.Context) string {
	return app.lastMessageCookie(c, SUCCESS_MESSAGE_COOKIE_NAME)
}

func (app *App) lastWarningMessage(c *echo.Context) string {
	return app.lastMessageCookie(c, WARNING_MESSAGE_COOKIE_NAME)
}

func (app *App) lastErrorMessage(c *echo.Context) string {
	return app.lastMessageCookie(c, ERROR_MESSAGE_COOKIE_NAME)
}

func getReturnURL(app *App, c *echo.Context) string {
	if (*c).FormValue("returnUrl") != "" {
		return (*c).FormValue("returnUrl")
	}
	return app.FrontEndURL
}

// Authenticate a user using the `browserToken` cookie, and call `f` with a
// reference to the user
func withBrowserAuthentication(app *App, requireLogin bool, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	return func(c echo.Context) error {
		destination := c.Request().URL.String()
		if c.Request().Method != "GET" {
			destination = getReturnURL(app, &c)
		}
		returnURL, err := addDestination(app.FrontEndURL, destination)
		if err != nil {
			return err
		}

		cookie, err := c.Cookie(BROWSER_TOKEN_COOKIE_NAME)

		var user User
		if err != nil || cookie.Value == "" {
			if requireLogin {
				return NewWebError(returnURL, "You are not logged in.")
			}
			return f(c, nil)
		} else {
			result := app.DB.First(&user, "browser_token = ?", cookie.Value)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					if requireLogin {
						app.setBrowserToken(&c, "")
						return NewWebError(returnURL, "You are not logged in.")
					}
					return f(c, nil)
				}
				return err
			}
			if user.IsLocked {
				app.setBrowserToken(&c, "")
				return NewWebError(returnURL, "That account is locked.")
			}
			return f(c, &user)
		}
	}
}

func withBrowserAdmin(app *App, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		if !user.IsAdmin {
			return NewWebError(returnURL, "You are not an admin.")
		}

		return f(c, user)
	})
}

func EncodeOIDCState(state oidcState) (string, error) {
	nonce, err := RandomHex(32)
	if err != nil {
		return "", err
	}
	state.Nonce = nonce
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(stateBytes), nil
}

// GET /
func FrontRoot(app *App) func(c echo.Context) error {
	type rootContext struct {
		App              *App
		User             *User
		URL              string
		Destination      string
		SuccessMessage   string
		WarningMessage   string
		ErrorMessage     string
		WebOIDCProviders []webOIDCProvider
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		destination := c.QueryParam("destination")
		webOIDCProviders := make([]webOIDCProvider, 0, len(app.OIDCProvidersByName))
		if len(app.OIDCProvidersByName) > 0 {
			stateBase64, err := EncodeOIDCState(oidcState{Action: OIDCActionSignIn, Destination: destination})
			if err != nil {
				return err
			}

			c.SetCookie(&http.Cookie{
				Name:     OIDC_STATE_COOKIE_NAME,
				Value:    stateBase64,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				HttpOnly: true,
				Secure:   true,
			})

			for name, provider := range app.OIDCProvidersByName {
				webOIDCProviders = append(webOIDCProviders, webOIDCProvider{
					Name:          name,
					RequireInvite: provider.Config.RequireInvite,
					AuthURL:       rp.AuthURL(stateBase64, provider.RelyingParty),
				})
			}
		}

		return c.Render(http.StatusOK, "root", rootContext{
			App:              app,
			User:             user,
			URL:              c.Request().URL.RequestURI(),
			Destination:      destination,
			SuccessMessage:   app.lastSuccessMessage(&c),
			WarningMessage:   app.lastWarningMessage(&c),
			ErrorMessage:     app.lastErrorMessage(&c),
			WebOIDCProviders: webOIDCProviders,
		})
	})
}

type webManifestIcon struct {
	Src   string `json:"src"`
	Type  string `json:"type"`
	Sizes string `json:"sizes"`
}

type webManifest struct {
	Icons []webManifestIcon `json:"icons"`
}

func FrontWebManifest(app *App) func(c echo.Context) error {
	url, err := url.JoinPath(app.FrontEndURL, "web/icon.png")
	Check(err)

	manifest := webManifest{
		Icons: []webManifestIcon{{
			Src:   url,
			Type:  "image/png",
			Sizes: "512x512",
		}},
	}
	manifestBlob := Unwrap(json.Marshal(manifest))
	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, manifestBlob)
	}
}

type webOIDCProvider struct {
	Name          string
	RequireInvite bool
	AuthURL       string
}

const (
	OIDCActionSignIn string = "sign-in"
	OIDCActionLink   string = "link"
)

type oidcState struct {
	Nonce       string `json:"nonce"`
	Action      string `json:"action"`
	Destination string `json:"destination,omitempty"`
	InviteCode  string `json:"inviteCode,omitempty"`
}

// GET /registration
func FrontRegistration(app *App) func(c echo.Context) error {
	type registrationContext struct {
		App              *App
		User             *User
		URL              string
		SuccessMessage   string
		WarningMessage   string
		ErrorMessage     string
		InviteCode       string
		WebOIDCProviders []webOIDCProvider
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		inviteCode := c.QueryParam("invite")
		webOIDCProviders := make([]webOIDCProvider, 0, len(app.OIDCProvidersByName))

		stateBase64, err := EncodeOIDCState(oidcState{Action: OIDCActionSignIn, InviteCode: inviteCode})
		if err != nil {
			return err
		}

		c.SetCookie(&http.Cookie{
			Name:     OIDC_STATE_COOKIE_NAME,
			Value:    stateBase64,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true,
			Secure:   true,
		})

		for name, provider := range app.OIDCProvidersByName {
			webOIDCProviders = append(webOIDCProviders, webOIDCProvider{
				Name:          name,
				RequireInvite: provider.Config.RequireInvite,
				AuthURL:       rp.AuthURL(stateBase64, provider.RelyingParty),
			})
		}

		return c.Render(http.StatusOK, "registration", registrationContext{
			App:              app,
			User:             user,
			URL:              c.Request().URL.RequestURI(),
			SuccessMessage:   app.lastSuccessMessage(&c),
			WarningMessage:   app.lastWarningMessage(&c),
			ErrorMessage:     app.lastErrorMessage(&c),
			InviteCode:       inviteCode,
			WebOIDCProviders: webOIDCProviders,
		})
	})
}

func (app *App) getPreferredPlayerName(userInfo *oidc.UserInfo) mo.Option[string] {
	preferredPlayerName := userInfo.PreferredUsername
	if preferredPlayerName == "" {
		return mo.None[string]()
	}
	if index := strings.IndexByte(userInfo.PreferredUsername, '@'); index >= 0 {
		preferredPlayerName = userInfo.PreferredUsername[:index]
	}
	if app.ValidatePlayerName(preferredPlayerName) != nil {
		return mo.None[string]()
	}
	return mo.Some(preferredPlayerName)
}

func (app *App) getIDTokenCookie(c *echo.Context) (string, oidc.IDTokenClaims, error) {
	cookie, err := (*c).Cookie(ID_TOKEN_COOKIE_NAME)
	if err != nil || cookie.Value == "" {
		return "", oidc.IDTokenClaims{}, &UserError{Err: errors.New("Missing ID token cookie")}
	}

	idTokenBytes, err := app.DecryptCookieValue(cookie.Value)
	if err != nil {
		return "", oidc.IDTokenClaims{}, &UserError{Err: errors.New("Invalid ID token")}
	}
	idToken := string(idTokenBytes)

	var claims oidc.IDTokenClaims
	_, err = oidc.ParseToken(idToken, &claims)
	if err != nil {
		return "", oidc.IDTokenClaims{}, &UserError{Err: errors.New("Invalid ID token.")}
	}

	return idToken, claims, nil
}

func FrontCompleteRegistration(app *App) func(c echo.Context) error {
	type completeRegistrationContext struct {
		App                 *App
		User                *User
		URL                 string
		SuccessMessage      string
		WarningMessage      string
		ErrorMessage        string
		InviteCode          string
		AnyUnmigratedUsers  bool
		PreferredPlayerName string
	}

	returnURL := Unwrap(url.JoinPath(app.FrontEndURL, "web/registration"))

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		inviteCode := c.QueryParam("invite")

		_, claims, err := app.getIDTokenCookie(&c)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: returnURL, Err: userError.Err}
			}
			return err
		}

		preferredPlayerName := app.getPreferredPlayerName(claims.GetUserInfo()).OrElse("")

		var anyUnmigratedUsers bool
		err = app.DB.Raw(`
			SELECT EXISTS (
				SELECT 1 from users u
				WHERE NOT EXISTS (
					SELECT 1 FROM user_oidc_identities uoi WHERE uoi.user_uuid = u.uuid
				)
			)
		`).Scan(&anyUnmigratedUsers).Error
		if err != nil {
			return err
		}

		return c.Render(http.StatusOK, "complete-registration", completeRegistrationContext{
			App:                 app,
			User:                user,
			URL:                 c.Request().URL.RequestURI(),
			SuccessMessage:      app.lastSuccessMessage(&c),
			WarningMessage:      app.lastWarningMessage(&c),
			ErrorMessage:        app.lastErrorMessage(&c),
			InviteCode:          inviteCode,
			PreferredPlayerName: preferredPlayerName,
			AnyUnmigratedUsers:  anyUnmigratedUsers,
		})
	})
}

func (app *App) FrontOIDCUnlink() func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		targetUUID := c.FormValue("userUuid")
		providerName := c.FormValue("providerName")

		if err := app.DeleteOIDCIdentity(user, targetUUID, providerName); err != nil {
			return err
		}

		app.setSuccessMessage(&c, "%s account unlinked.", providerName)
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

func (app *App) oidcLink(c echo.Context, user *User) error {
	returnURL := Unwrap(url.JoinPath(app.FrontEndURL, "web/user"))

	if user == nil {
		return NewWebError(app.FrontEndURL, "You are not logged in.")
	}

	providerName := c.Param("providerName")
	oidcProvider, ok := app.OIDCProvidersByName[providerName]
	if !ok {
		return NewWebError(returnURL, "Unknown OIDC provider: %s", providerName)
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.Background(), c.FormValue("code"), oidcProvider.RelyingParty)
	if err != nil {
		return NewWebError(returnURL, "OIDC code exchange failed.")
	}

	_, err = app.CreateOIDCIdentity(user, user.UUID, tokens.IDToken)
	if err != nil {
		var userError *UserError
		if errors.As(err, &userError) {
			return &WebError{ReturnURL: returnURL, Err: userError.Err}
		}
		return err
	}

	app.setSuccessMessage(&c, "Successfully linked your %s account.", providerName)

	return c.Redirect(http.StatusSeeOther, returnURL)
}

func (app *App) oidcSignIn(c echo.Context, state oidcState) error {
	failureURL, err := url.JoinPath(app.FrontEndURL, "web/registration")
	if err != nil {
		return err
	}
	completeRegistrationURL, err := url.JoinPath(app.FrontEndURL, "web/complete-registration")
	if err != nil {
		return err
	}

	if state.InviteCode != "" {
		var err error
		completeRegistrationURL, err = SetQueryParam(completeRegistrationURL, "invite", state.InviteCode)
		if err != nil {
			return err
		}
		failureURL, err = SetQueryParam(failureURL, "invite", state.InviteCode)
		if err != nil {
			return err
		}
	}

	providerName := c.Param("providerName")
	oidcProvider, ok := app.OIDCProvidersByName[providerName]
	if !ok {
		return NewWebError(failureURL, "Unknown OIDC provider: %s", providerName)
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.Background(), c.FormValue("code"), oidcProvider.RelyingParty)
	if err != nil {
		return NewWebError(failureURL, "OIDC code exchange failed.")
	}

	var claims oidc.IDTokenClaims
	_, err = oidc.ParseToken(tokens.IDToken, &claims)
	if err != nil {
		return err
	}

	var oidcIdentity UserOIDCIdentity
	result := app.DB.Preload("User").First(&oidcIdentity, "subject = ? AND issuer = ?", claims.Subject, claims.Issuer)
	if result.Error == nil {
		// User already exists, log in
		user := oidcIdentity.User

		if user.IsLocked {
			return NewWebError(failureURL, "Account is locked.")
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}
		user.BrowserToken = MakeNullString(&browserToken)
		if err := app.DB.Save(&user).Error; err != nil {
			return err
		}
		app.setBrowserToken(&c, browserToken)

		returnURL, err := url.JoinPath(app.FrontEndURL, "web/user")
		if err != nil {
			return err
		}

		if state.Destination != "" {
			returnURL = state.Destination
		}
		return c.Redirect(http.StatusSeeOther, returnURL)
	} else {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return result.Error
		}
	}

	encryptedIDToken, err := app.EncryptCookieValue(tokens.IDToken)
	if err != nil {
		return err
	}

	// User doesn't already exist, set ID token cookie and complete registration
	c.SetCookie(&http.Cookie{
		Name:     ID_TOKEN_COOKIE_NAME,
		Value:    encryptedIDToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   true,
	})

	return c.Redirect(http.StatusSeeOther, completeRegistrationURL)
}

// GET /oidc-callback/:providerName
func FrontOIDCCallback(app *App) func(c echo.Context) error {
	failureURL := app.FrontEndURL

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		stateCookie, err := c.Cookie(OIDC_STATE_COOKIE_NAME)
		if err != nil {
			return NewWebError(failureURL, "Missing state cookie")
		}
		c.SetCookie(&http.Cookie{
			Name:     OIDC_STATE_COOKIE_NAME,
			Value:    "",
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			HttpOnly: true,
			Secure:   true,
		})

		stateParam := c.QueryParam("state")
		if stateCookie.Value != stateParam {
			fmt.Println("stateCookie.Value", stateCookie.Value, "stateParam", stateParam)
			return NewWebError(failureURL, "\"state\" param doesn't match \"%s\" cookie.", OIDC_STATE_COOKIE_NAME)
		}

		stateBytes, err := base64.StdEncoding.DecodeString(stateParam)
		if err != nil {
			return NewWebError(failureURL, "Invalid OIDC state cookie")
		}

		var state oidcState
		err = json.Unmarshal(stateBytes, &state)
		if err != nil {
			return NewWebError(failureURL, "Invalid OIDC state cookie")
		}

		switch state.Action {
		case OIDCActionSignIn:
			return app.oidcSignIn(c, state)
		case OIDCActionLink:
			return app.oidcLink(c, user)
		default:
			return NewWebError(failureURL, "Unknown OIDC action: %s", state.Action)
		}
	})
}

// GET /web/admin
func FrontAdmin(app *App) func(c echo.Context) error {
	type adminContext struct {
		App            *App
		User           *User
		URL            string
		SuccessMessage string
		WarningMessage string
		ErrorMessage   string
		Users          []User
		Invites        []Invite
	}

	return withBrowserAdmin(app, func(c echo.Context, user *User) error {
		var users []User
		result := app.DB.Find(&users)
		if result.Error != nil {
			return result.Error
		}

		var invites []Invite
		result = app.DB.Find(&invites)
		if result.Error != nil {
			return result.Error
		}

		return c.Render(http.StatusOK, "admin", adminContext{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			SuccessMessage: app.lastSuccessMessage(&c),
			WarningMessage: app.lastWarningMessage(&c),
			ErrorMessage:   app.lastErrorMessage(&c),
			Users:          users,
			Invites:        invites,
		})
	})
}

// POST /web/admin/delete-invite
func FrontDeleteInvite(app *App) func(c echo.Context) error {
	returnURL := Unwrap(url.JoinPath(app.FrontEndURL, "web/admin"))

	return withBrowserAdmin(app, func(c echo.Context, user *User) error {
		inviteCode := c.FormValue("inviteCode")

		var invite Invite
		result := app.DB.Where("code = ?", inviteCode).Delete(&invite)
		if result.Error != nil {
			return result.Error
		}

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/admin/update-users
func FrontUpdateUsers(app *App) func(c echo.Context) error {
	return withBrowserAdmin(app, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		var users []User
		result := app.DB.Find(&users)
		if result.Error != nil {
			return result.Error
		}

		tx := app.DB.Begin()
		defer tx.Rollback()

		anyUnlockedAdmins := false
		for _, targetUser := range users {
			shouldBeAdmin := c.FormValue("admin-"+targetUser.UUID) == "on"
			if app.IsDefaultAdmin(&targetUser) {
				shouldBeAdmin = true
			}

			shouldBeLocked := c.FormValue("locked-"+targetUser.UUID) == "on"
			if shouldBeAdmin && !shouldBeLocked {
				anyUnlockedAdmins = true
			}

			maxPlayerCountString := c.FormValue("max-player-count-" + targetUser.UUID)
			maxPlayerCount := targetUser.MaxPlayerCount
			if maxPlayerCountString == "" {
				maxPlayerCount = app.Constants.MaxPlayerCountUseDefault
			} else {
				var err error
				maxPlayerCount, err = strconv.Atoi(maxPlayerCountString)
				if err != nil {
					return NewWebError(returnURL, "Max player count must be an integer.")
				}
			}

			if targetUser.IsAdmin != shouldBeAdmin || targetUser.IsLocked != shouldBeLocked || targetUser.MaxPlayerCount != maxPlayerCount {
				_, err := app.UpdateUser(
					tx,
					user,       // caller
					targetUser, // user
					nil,
					&shouldBeAdmin,  // isAdmin
					&shouldBeLocked, // isLocked
					false,
					false,
					nil,
					&maxPlayerCount,
				)
				if err != nil {
					var userError *UserError
					if errors.As(err, &userError) {
						return &WebError{ReturnURL: returnURL, Err: userError.Err}
					}
					return err
				}
			}
		}

		if !anyUnlockedAdmins {
			return NewWebError(returnURL, "There must be at least one unlocked admin account.")
		}

		err := tx.Commit().Error
		if err != nil {
			return err
		}

		app.setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/admin/new-invite
func FrontNewInvite(app *App) func(c echo.Context) error {
	return withBrowserAdmin(app, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		_, err := app.CreateInvite()
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: returnURL, Err: userError.Err}
			}
			return err
		}

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// GET /web/user
// GET /web/user/:uuid
func FrontUser(app *App) func(c echo.Context) error {
	type userContext struct {
		App                     *App
		User                    *User
		URL                     string
		SuccessMessage          string
		WarningMessage          string
		ErrorMessage            string
		TargetUser              *User
		TargetUserID            string
		SkinURL                 *string
		CapeURL                 *string
		AdminView               bool
		MaxPlayerCount          int
		LinkedOIDCProviderNames []string
		UnlinkedOIDCProviders   []webOIDCProvider
	}

	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		var targetUser *User
		targetUUID := c.Param("uuid")
		adminView := false
		if targetUUID == "" || targetUUID == user.UUID {
			var targetUserStruct User
			result := app.DB.First(&targetUserStruct, "uuid = ?", user.UUID)
			if result.Error != nil {
				return result.Error
			}
			targetUser = &targetUserStruct
		} else {
			if !user.IsAdmin {
				return NewWebError(app.FrontEndURL, "You are not an admin.")
			}
			adminView = true
			var targetUserStruct User
			result := app.DB.First(&targetUserStruct, "uuid = ?", targetUUID)
			if result.Error != nil {
				returnURL, err := url.JoinPath(app.FrontEndURL, "web/admin")
				if err != nil {
					return err
				}
				return NewWebError(returnURL, "User not found.")
			}
			targetUser = &targetUserStruct
		}

		maxPlayerCount := app.GetMaxPlayerCount(targetUser)

		linkedOIDCProviderNames := mapset.NewSet[string]()
		unlinkedOIDCProviders := make([]webOIDCProvider, 0, len(app.OIDCProvidersByName))

		if len(app.OIDCProvidersByName) > 0 {
			stateBase64, err := EncodeOIDCState(oidcState{Action: OIDCActionLink})
			if err != nil {
				return err
			}

			c.SetCookie(&http.Cookie{
				Name:     OIDC_STATE_COOKIE_NAME,
				Value:    stateBase64,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				HttpOnly: true,
				Secure:   true,
			})

			for _, oidcIdentity := range targetUser.OIDCIdentities {
				if oidcProvider, ok := app.OIDCProvidersByIssuer[oidcIdentity.Issuer]; ok {
					linkedOIDCProviderNames.Add(oidcProvider.Config.Name)
				}
			}
			for name, provider := range app.OIDCProvidersByName {
				if !linkedOIDCProviderNames.Contains(name) {
					unlinkedOIDCProviders = append(unlinkedOIDCProviders, webOIDCProvider{
						Name:    name,
						AuthURL: rp.AuthURL(stateBase64, provider.RelyingParty),
					})
				}
			}
		}

		return c.Render(http.StatusOK, "user", userContext{
			App:                     app,
			User:                    user,
			URL:                     c.Request().URL.RequestURI(),
			SuccessMessage:          app.lastSuccessMessage(&c),
			WarningMessage:          app.lastWarningMessage(&c),
			ErrorMessage:            app.lastErrorMessage(&c),
			TargetUser:              targetUser,
			AdminView:               adminView,
			LinkedOIDCProviderNames: linkedOIDCProviderNames.ToSlice(),
			UnlinkedOIDCProviders:   unlinkedOIDCProviders,
			MaxPlayerCount:          maxPlayerCount,
		})
	})
}

// GET /web/player/:uuid
func FrontPlayer(app *App) func(c echo.Context) error {
	type playerContext struct {
		App            *App
		User           *User
		URL            string
		SuccessMessage string
		WarningMessage string
		ErrorMessage   string
		Player         *Player
		PlayerID       string
		SkinURL        *string
		CapeURL        *string
		AdminView      bool
	}

	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		playerUUID := c.Param("uuid")

		var player Player
		result := app.DB.Preload("User").First(&player, "uuid = ?", playerUUID)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return NewWebError(returnURL, "Player not found.")
			}
			return result.Error
		}
		playerUser := player.User

		if !user.IsAdmin && (player.User.UUID != user.UUID) {
			return NewWebError(app.FrontEndURL, "You don't own that player.")
		}
		adminView := playerUser.UUID != user.UUID

		skinURL, err := app.GetSkinURL(&player)
		if err != nil {
			return err
		}
		capeURL, err := app.GetCapeURL(&player)
		if err != nil {
			return err
		}

		id, err := UUIDToID(player.UUID)
		if err != nil {
			return err
		}

		return c.Render(http.StatusOK, "player", playerContext{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			SuccessMessage: app.lastSuccessMessage(&c),
			WarningMessage: app.lastWarningMessage(&c),
			ErrorMessage:   app.lastErrorMessage(&c),
			Player:         &player,
			PlayerID:       id,
			SkinURL:        skinURL,
			CapeURL:        capeURL,
			AdminView:      adminView,
		})
	})
}

func nilIfEmpty(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

func getFormValue(c *echo.Context, key string) mo.Option[string] {
	// Call FormValue first to parse the form appropriately
	value := (*c).FormValue(key)
	if (*c).Request().Form.Has(key) {
		return mo.Some(value)
	}
	return mo.None[string]()
}

// POST /update-user
func FrontUpdateUser(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		targetUUID := nilIfEmpty(c.FormValue("uuid"))
		password := nilIfEmpty(c.FormValue("password"))
		resetAPIToken := c.FormValue("resetApiToken") == "on"
		resetMinecraftToken := c.FormValue("resetMinecraftToken") == "on"
		preferredLanguage := nilIfEmpty(c.FormValue("preferredLanguage"))
		maybeMaxPlayerCountString := getFormValue(&c, "maxPlayerCount")

		var targetUser *User
		if targetUUID == nil || *targetUUID == user.UUID {
			targetUser = user
		} else {
			if !user.IsAdmin {
				return NewWebError(app.FrontEndURL, "You are not an admin.")
			}
			var targetUserStruct User
			result := app.DB.First(&targetUserStruct, "uuid = ?", targetUUID)
			targetUser = &targetUserStruct
			if result.Error != nil {
				return NewWebError(returnURL, "User not found.")
			}
		}

		maybeMaxPlayerCount := mo.None[int]()
		if maxPlayerCountString, ok := maybeMaxPlayerCountString.Get(); ok {
			if maxPlayerCountString == "" {
				maybeMaxPlayerCount = mo.Some(app.Constants.MaxPlayerCountUseDefault)
			} else {
				var err error
				maxPlayerCount, err := strconv.Atoi(maxPlayerCountString)
				if err != nil {
					return NewWebError(returnURL, "Max player count must be an integer.")
				}
				maybeMaxPlayerCount = mo.Some(maxPlayerCount)
			}
		}

		_, err := app.UpdateUser(
			app.DB,
			user,        // caller
			*targetUser, // user
			password,
			nil, // isAdmin
			nil, // isLocked
			resetAPIToken,
			resetMinecraftToken,
			preferredLanguage,
			maybeMaxPlayerCount.ToPointer(),
		)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: returnURL, Err: userError.Err}
			}
			return err
		}

		app.setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/update-player
func FrontUpdatePlayer(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		playerUUID := c.FormValue("uuid")
		playerName := nilIfEmpty(c.FormValue("playerName"))
		fallbackPlayer := nilIfEmpty(c.FormValue("fallbackPlayer"))
		skinModel := nilIfEmpty(c.FormValue("skinModel"))
		skinURL := nilIfEmpty(c.FormValue("skinUrl"))
		deleteSkin := c.FormValue("deleteSkin") == "on"
		capeURL := nilIfEmpty(c.FormValue("capeUrl"))
		deleteCape := c.FormValue("deleteCape") == "on"

		var player Player
		result := app.DB.Preload("User").First(&player, "uuid = ?", playerUUID)
		if result.Error != nil {
			return NewWebError(returnURL, "Player not found.")
		}

		// Skin
		var skinReader *io.Reader
		skinFile, skinFileErr := c.FormFile("skinFile")
		if skinFileErr == nil {
			var err error
			skinHandle, err := skinFile.Open()
			if err != nil {
				return err
			}
			defer skinHandle.Close()
			var skinFileReader io.Reader = skinHandle
			skinReader = &skinFileReader
		}

		// Cape
		var capeReader *io.Reader
		capeFile, capeFileErr := c.FormFile("capeFile")
		if capeFileErr == nil {
			var err error
			capeHandle, err := capeFile.Open()
			if err != nil {
				return err
			}
			defer capeHandle.Close()
			var capeFileReader io.Reader = capeHandle
			capeReader = &capeFileReader
		}

		_, err := app.UpdatePlayer(
			user, // caller
			player,
			playerName,
			fallbackPlayer,
			skinModel,
			skinReader,
			skinURL,
			deleteSkin,
			capeReader,
			capeURL,
			deleteCape,
		)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: returnURL, Err: userError.Err}
			}
			return err
		}

		app.setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/logout
func FrontLogout(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := app.FrontEndURL
		user.BrowserToken = MakeNullString(nil)
		if err := app.DB.Save(user).Error; err != nil {
			return err
		}
		app.setBrowserToken(&c, "")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

const (
	ChallengeActionRegister     string = "register"
	ChallengeActionCreatePlayer string = "create-player"
)

// GET /web/create-player-challenge
func FrontCreatePlayerChallenge(app *App) func(c echo.Context) error {
	return frontChallenge(app, ChallengeActionCreatePlayer)
}

// GET /web/register-challenge
func FrontRegisterChallenge(app *App) func(c echo.Context) error {
	return frontChallenge(app, ChallengeActionRegister)
}

func frontChallenge(app *App, action string) func(c echo.Context) error {
	type challengeContext struct {
		App                  *App
		User                 *User
		URL                  string
		SuccessMessage       string
		WarningMessage       string
		ErrorMessage         string
		PlayerName           string
		RegistrationProvider string
		SkinBase64           string
		SkinFilename         string
		ChallengeToken       string
		InviteCode           string
		UseIDToken           bool
		Action               string
		UserUUID             *string
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		useIDToken := c.QueryParam("useIdToken") == "on"

		var playerName string
		var userUUID *string
		if action == ChallengeActionRegister {
			username := c.QueryParam("username")
			if err := app.ValidateUsername(username); err != nil {
				return NewWebError(returnURL, "Invalid username: %s", err)
			}
			playerName = username
		} else if action == ChallengeActionCreatePlayer {
			playerName = c.QueryParam("playerName")
			userUUIDString := c.QueryParam("userUuid")
			userUUID = &userUUIDString
		}

		if err := app.ValidatePlayerName(playerName); err != nil {
			return NewWebError(returnURL, "Invalid player name: %s", err)
		}

		inviteCode := c.QueryParam("inviteCode")

		var challengeToken string
		cookie, err := c.Cookie(CHALLENGE_TOKEN_COOKIE_NAME)
		if err != nil || cookie.Value == "" {
			challengeToken, err = MakeChallengeToken()
			if err != nil {
				return err
			}
			c.SetCookie(&http.Cookie{
				Name:     CHALLENGE_TOKEN_COOKIE_NAME,
				Value:    challengeToken,
				MaxAge:   BROWSER_TOKEN_AGE_SEC,
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				HttpOnly: true,
				Secure:   true,
			})
		} else {
			challengeToken = cookie.Value
		}

		challengeSkinBytes, err := app.GetChallengeSkin(playerName, challengeToken)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return NewWebError(returnURL, "Error: %s", userError.Err.Error())
			}
			return err
		}
		skinBase64 := base64.StdEncoding.EncodeToString(challengeSkinBytes)

		return c.Render(http.StatusOK, "challenge", challengeContext{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			SuccessMessage: app.lastSuccessMessage(&c),
			WarningMessage: app.lastWarningMessage(&c),
			ErrorMessage:   app.lastErrorMessage(&c),
			PlayerName:     playerName,
			SkinBase64:     skinBase64,
			SkinFilename:   playerName + "-challenge.png",
			ChallengeToken: challengeToken,
			InviteCode:     inviteCode,
			UseIDToken:     useIDToken,
			Action:         action,
			UserUUID:       userUUID,
		})
	})
}

// POST /web/create-player
func FrontCreatePlayer(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, caller *User) error {
		userUUID := c.FormValue("userUuid")

		playerName := c.FormValue("playerName")
		chosenUUID := nilIfEmpty(c.FormValue("playerUuid"))
		existingPlayer := c.FormValue("existingPlayer") == "on"
		challengeToken := nilIfEmpty(c.FormValue("challengeToken"))

		failureURL := getReturnURL(app, &c)

		player, err := app.CreatePlayer(
			caller,
			userUUID,
			playerName,
			chosenUUID,
			existingPlayer,
			challengeToken,
			nil, // fallbackPlayer
			nil, // skinModel
			nil, // skinReader
			nil, // skinURL
			nil, // capeReader
			nil, // capeURL
		)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
			return err
		}

		returnURL, err := url.JoinPath(app.FrontEndURL, "web/player", player.UUID)
		if err != nil {
			return err
		}
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/register
func FrontRegister(app *App) func(c echo.Context) error {
	returnURL := Unwrap(url.JoinPath(app.FrontEndURL, "web/user"))
	return func(c echo.Context) error {
		playerName := c.FormValue("playerName")
		honeypot := c.FormValue("email")
		chosenUUID := nilIfEmpty(c.FormValue("uuid"))
		existingPlayer := c.FormValue("existingPlayer") == "on"
		useIDToken := c.FormValue("useIdToken") == "on"
		challengeToken := nilIfEmpty(c.FormValue("challengeToken"))
		inviteCode := nilIfEmpty(c.FormValue("inviteCode"))
		password := getFormValue(&c, "password")

		failureURL := getReturnURL(app, &c)
		noInviteFailureURL, err := UnsetQueryParam(failureURL, "invite")
		if err != nil {
			return err
		}

		if honeypot != "" {
			return NewWebError(failureURL, "You are now covered in bee stings.")
		}

		username := playerName
		idTokens := []string{}
		if useIDToken {
			idToken, claims, err := app.getIDTokenCookie(&c)
			if err != nil {
				var userError *UserError
				if errors.As(err, &userError) {
					return &WebError{ReturnURL: failureURL, Err: userError.Err}
				}
				return err
			}

			username = claims.Email
			idTokens = []string{idToken}
		}

		user, err := app.CreateUser(
			nil, // caller
			username,
			password.ToPointer(),
			idTokens,
			false, // isAdmin
			false, // isLocked
			inviteCode,
			nil, // preferredLanguage
			&playerName,
			chosenUUID,
			existingPlayer,
			challengeToken,
			nil, // fallbackPlayer
			nil, // maxPlayerCount
			nil, // skinModel
			nil, // skinReader
			nil, // skinURL
			nil, // capeReader
			nil, // capeURL
		)
		if err != nil {
			if err == InviteNotFoundError || err == InviteMissingError {
				return &WebError{ReturnURL: noInviteFailureURL, Err: err}
			}

			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
			return err
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}
		user.BrowserToken = MakeNullString(&browserToken)
		if err := app.DB.Save(&user).Error; err != nil {
			return err
		}
		app.setBrowserToken(&c, browserToken)

		if useIDToken {
			c.SetCookie(&http.Cookie{
				Name:     ID_TOKEN_COOKIE_NAME,
				Value:    "",
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
				HttpOnly: true,
				Secure:   true,
			})
		}

		app.setSuccessMessage(&c, "Account created.")

		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

func addDestination(url_ string, destination string) (string, error) {
	if destination == "" {
		return url_, nil
	} else if url_ == destination {
		return url_, nil
	} else {
		urlStruct, err := url.Parse(url_)
		if err != nil {
			return "", err
		}
		query := urlStruct.Query()
		query.Set("destination", destination)
		urlStruct.RawQuery = query.Encode()
		return urlStruct.String(), nil
	}
}

// POST /web/oidc-migrate
func (app *App) FrontOIDCMigrate() func(c echo.Context) error {
	return func(c echo.Context) error {
		failureURL := getReturnURL(app, &c)

		username := c.FormValue("username")
		password := c.FormValue("password")

		idToken, claims, err := app.getIDTokenCookie(&c)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
			return err
		}
		provider, ok := app.OIDCProvidersByIssuer[claims.Issuer]
		if !ok {
			return NewWebError(failureURL, "Unknown OIDC provider: %s", claims.Issuer)
		}

		user, err := app.AuthenticateUserForMigration(username, password)
		if err != nil {
			var userError *UserError
			if err == PasswordLoginNotAllowedError {
				return NewWebError(failureURL, "That account is already migrated. Log in via OpenID Connect.")
			}
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
		}

		_, err = app.CreateOIDCIdentity(&user, user.UUID, idToken)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
			return err
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}
		user.BrowserToken = MakeNullString(&browserToken)
		if err := app.DB.Save(&user).Error; err != nil {
			return err
		}
		app.setBrowserToken(&c, browserToken)

		returnURL, err := url.JoinPath(app.FrontEndURL, "web/user")
		if err != nil {
			return err
		}

		app.setSuccessMessage(&c, "Successfully migrated account. From now on, log in with %s.", provider.Config.Name)
		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

// POST /web/login
func FrontLogin(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		failureURL := getReturnURL(app, &c)

		username := c.FormValue("username")
		password := c.FormValue("password")

		user, err := app.AuthenticateUser(username, password)
		if err != nil {
			var userError *UserError
			if err == PasswordLoginNotAllowedError {
				return NewWebError(failureURL, "%s Log in via OpenID Connect instead.", err.Error())
			}
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: failureURL, Err: userError.Err}
			}
			return err
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}
		user.BrowserToken = MakeNullString(&browserToken)
		if err := app.DB.Save(&user).Error; err != nil {
			return err
		}
		app.setBrowserToken(&c, browserToken)

		returnURL, err := url.JoinPath(app.FrontEndURL, "web/user")
		if err != nil {
			return err
		}
		destination := c.FormValue("destination")
		if destination != "" {
			returnURL = destination
		}
		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

// POST /web/delete-user
func FrontDeleteUser(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		var targetUser *User
		targetUUID := c.FormValue("uuid")
		if targetUUID == "" || targetUUID == user.UUID {
			targetUser = user
		} else {
			if !user.IsAdmin {
				return NewWebError(app.FrontEndURL, "You are not an admin.")
			}
			var targetUserStruct User
			if err := app.DB.First(&targetUserStruct, "uuid = ?", targetUUID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return NewWebError(returnURL, "User not found.")
				}
				return err
			}
			targetUser = &targetUserStruct
		}

		err := app.DeleteUser(user, targetUser)
		if err != nil {
			return err
		}

		if targetUser == user {
			app.setBrowserToken(&c, "")
		}
		app.setSuccessMessage(&c, "Account deleted")

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /web/delete-player
func FrontDeletePlayer(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

		playerUUID := c.FormValue("uuid")

		var player Player
		result := app.DB.Preload("User").First(&player, "uuid = ?", playerUUID)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return NewWebError(returnURL, "Player not found.")
			}
			return result.Error
		}

		err := app.DeletePlayer(user, &player)
		if err != nil {
			var userError *UserError
			if errors.As(err, &userError) {
				return &WebError{ReturnURL: returnURL, Err: userError.Err}
			}
		}

		app.setSuccessMessage(&c, "Player \"%s\" deleted", player.Name)

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}
