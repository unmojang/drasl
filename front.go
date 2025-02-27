package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"gorm.io/gorm"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
)

/*
Web front end for creating user accounts, changing passwords, skins, player names, etc.
*/

const BROWSER_TOKEN_AGE_SEC = 24 * 60 * 60

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

func setSuccessMessage(c *echo.Context, message string) {
	(*c).SetCookie(&http.Cookie{
		Name:     "successMessage",
		Value:    url.QueryEscape(message),
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})
}

// Set a warning message
func setWarningMessage(c *echo.Context, message string) {
	(*c).SetCookie(&http.Cookie{
		Name:     "warningMessage",
		Value:    url.QueryEscape(message),
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})
}

// Set an error message cookie
func setErrorMessage(c *echo.Context, message string) {
	(*c).SetCookie(&http.Cookie{
		Name:     "errorMessage",
		Value:    url.QueryEscape(message),
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
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
	if httpError, ok := err.(*echo.HTTPError); ok {
		switch httpError.Code {
		case http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
			if message, ok := httpError.Message.(string); ok {
				return (*c).String(httpError.Code, message)
			}
		}
	}

	var webError *WebError
	if errors.As(err, &webError) {
		setErrorMessage(c, webError.Error())
		return (*c).Redirect(http.StatusSeeOther, webError.ReturnURL)
	}

	app.LogError(err, c)
	return (*c).String(http.StatusInternalServerError, "Internal server error")
}

func lastSuccessMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("successMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	setSuccessMessage(c, "")
	return decoded
}

func lastWarningMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("warningMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	setWarningMessage(c, "")
	return decoded
}

// Read and clear the error message cookie
func lastErrorMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("errorMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	setErrorMessage(c, "")
	return decoded
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

		cookie, err := c.Cookie("browserToken")

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
						c.SetCookie(&http.Cookie{
							Name:     "browserToken",
							Value:    "",
							MaxAge:   -1,
							Path:     "/",
							SameSite: http.SameSiteStrictMode,
							HttpOnly: true,
						})
						return NewWebError(returnURL, "You are not logged in.")
					}
					return f(c, nil)
				}
				return err
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

// GET /
func FrontRoot(app *App) func(c echo.Context) error {
	type rootContext struct {
		App            *App
		User           *User
		URL            string
		Destination    string
		SuccessMessage string
		WarningMessage string
		ErrorMessage   string
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		return c.Render(http.StatusOK, "root", rootContext{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			Destination:    c.QueryParam("destination"),
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
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

// GET /registration
func FrontRegistration(app *App) func(c echo.Context) error {
	type context struct {
		App            *App
		User           *User
		URL            string
		SuccessMessage string
		WarningMessage string
		ErrorMessage   string
		InviteCode     string
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		inviteCode := c.QueryParam("invite")
		return c.Render(http.StatusOK, "registration", context{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
			InviteCode:     inviteCode,
		})
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
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
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

		setSuccessMessage(&c, "Changes saved.")
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

// GET /drasl/user
// GET /drasl/user/:uuid
func FrontUser(app *App) func(c echo.Context) error {
	type userContext struct {
		App            *App
		User           *User
		URL            string
		SuccessMessage string
		WarningMessage string
		ErrorMessage   string
		TargetUser     *User
		TargetUserID   string
		SkinURL        *string
		CapeURL        *string
		AdminView      bool
		MaxPlayerCount int
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

		return c.Render(http.StatusOK, "user", userContext{
			App:            app,
			User:           user,
			URL:            c.Request().URL.RequestURI(),
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
			TargetUser:     targetUser,
			// SkinURL:        skinURL,
			// CapeURL:        capeURL,
			AdminView:      adminView,
			MaxPlayerCount: maxPlayerCount,
		})
	})
}

// GET /drasl/player/:uuid
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
		if !user.IsAdmin && (player.User.UUID != user.UUID) {
			return NewWebError(app.FrontEndURL, "You don't own that player.")
		}
		adminView := player.User.UUID != user.UUID

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
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
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

		setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /update-player
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

		setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /logout
func FrontLogout(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, true, func(c echo.Context, user *User) error {
		returnURL := app.FrontEndURL
		c.SetCookie(&http.Cookie{
			Name:     "browserToken",
			Value:    "",
			MaxAge:   -1,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
		})
		user.BrowserToken = MakeNullString(nil)
		app.DB.Save(user)
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

const (
	ChallengeActionRegister     string = "register"
	ChallengeActionCreatePlayer string = "create-player"
)

// GET /create-player-challenge
func FrontCreatePlayerChallenge(app *App) func(c echo.Context) error {
	return frontChallenge(app, ChallengeActionCreatePlayer)
}

// GET /register-challenge
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
		Action               string
		UserUUID             *string
	}

	return withBrowserAuthentication(app, false, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(app, &c)

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
		cookie, err := c.Cookie("challengeToken")
		if err != nil || cookie.Value == "" {
			challengeToken, err = MakeChallengeToken()
			if err != nil {
				return err
			}
			c.SetCookie(&http.Cookie{
				Name:     "challengeToken",
				Value:    challengeToken,
				MaxAge:   BROWSER_TOKEN_AGE_SEC,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				HttpOnly: true,
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
			SuccessMessage: lastSuccessMessage(&c),
			WarningMessage: lastWarningMessage(&c),
			ErrorMessage:   lastErrorMessage(&c),
			PlayerName:     playerName,
			SkinBase64:     skinBase64,
			SkinFilename:   playerName + "-challenge.png",
			ChallengeToken: challengeToken,
			InviteCode:     inviteCode,
			Action:         action,
			UserUUID:       userUUID,
		})
	})
}

// POST /create-player
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

// POST /register
func FrontRegister(app *App) func(c echo.Context) error {
	returnURL := Unwrap(url.JoinPath(app.FrontEndURL, "web/user"))
	return func(c echo.Context) error {
		username := c.FormValue("username")
		honeypot := c.FormValue("email")
		password := c.FormValue("password")
		chosenUUID := nilIfEmpty(c.FormValue("uuid"))
		existingPlayer := c.FormValue("existingPlayer") == "on"
		challengeToken := nilIfEmpty(c.FormValue("challengeToken"))
		inviteCode := nilIfEmpty(c.FormValue("inviteCode"))

		failureURL := getReturnURL(app, &c)
		noInviteFailureURL, err := StripQueryParam(failureURL, "invite")
		if err != nil {
			return err
		}

		if honeypot != "" {
			setErrorMessage(&c, "You are now covered in bee stings.")
			return c.Redirect(http.StatusSeeOther, failureURL)
		}

		user, err := app.CreateUser(
			nil, // caller
			username,
			password,
			false, // isAdmin
			false, // isLocked
			inviteCode,
			nil, // preferredLanguage
			nil, // playerName
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
		result := app.DB.Save(&user)
		if result.Error != nil {
			return result.Error
		}

		c.SetCookie(&http.Cookie{
			Name:     "browserToken",
			Value:    browserToken,
			MaxAge:   BROWSER_TOKEN_AGE_SEC,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
		})

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

// POST /login
func FrontLogin(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		failureURL := getReturnURL(app, &c)

		username := c.FormValue("username")
		password := c.FormValue("password")

		if app.TransientLoginEligible(username) {
			return NewWebError(failureURL, "Transient accounts cannot access the web interface.")
		}

		var user User
		result := app.DB.First(&user, "username = ?", username)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return NewWebError(failureURL, "User not found!")
			}
			return result.Error
		}

		if user.IsLocked {
			return NewWebError(failureURL, "Account is locked.")
		}

		passwordHash, err := HashPassword(password, user.PasswordSalt)
		if err != nil {
			return err
		}

		if !bytes.Equal(passwordHash, user.PasswordHash) {
			return NewWebError(failureURL, "Incorrect password!")
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}

		c.SetCookie(&http.Cookie{
			Name:     "browserToken",
			Value:    browserToken,
			MaxAge:   BROWSER_TOKEN_AGE_SEC,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
		})

		user.BrowserToken = MakeNullString(&browserToken)
		app.DB.Save(&user)

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

// POST /delete-user
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
			c.SetCookie(&http.Cookie{
				Name:     "browserToken",
				Value:    "",
				MaxAge:   -1,
				Path:     "/",
				SameSite: http.SameSiteStrictMode,
				HttpOnly: true,
			})
		}
		setSuccessMessage(&c, "Account deleted")

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /delete-player
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

		setSuccessMessage(&c, fmt.Sprintf("Player \"%s\" deleted", player.Name))

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}
