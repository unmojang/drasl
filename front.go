package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"os"
	"time"
)

/*
Web front end for creating user accounts, changing passwords, skins, player names, etc.
*/

// Must be in a region of the skin that supports translucency
const SKIN_WINDOW_X_MIN = 40
const SKIN_WINDOW_X_MAX = 48
const SKIN_WINDOW_Y_MIN = 9
const SKIN_WINDOW_Y_MAX = 11

// https://echo.labstack.com/guide/templates/
// https://stackoverflow.com/questions/36617949/how-to-use-base-template-file-for-golang-html-template/69244593#69244593
type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, err := template.New("").ParseFiles("view/layout.html", "view/"+name+".html", "view/header.html")
	Check(err)
	return tmpl.ExecuteTemplate(w, "base", data)
}

// Set an error message cookie
func setErrorMessage(c *echo.Context, message string) {
	(*c).SetCookie(&http.Cookie{
		Name:  "errorMessage",
		Value: message,
	})
}

func setSuccessMessage(c *echo.Context, message string) {
	(*c).SetCookie(&http.Cookie{
		Name:  "successMessage",
		Value: message,
	})
}

func getReturnURL(c *echo.Context, fallback string) string {
	// TODO validate referrer
	referer := (*c).Request().Referer()
	if referer != "" {
		return referer
	}
	return fallback
}

// Read and clear the error message cookie
func lastErrorMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("errorMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	setErrorMessage(c, "")
	return cookie.Value
}

func lastSuccessMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("successMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	setSuccessMessage(c, "")
	return cookie.Value
}

// Authenticate a user using the `browserToken` cookie, and call `f` with a
// reference to the user
func withBrowserAuthentication(app *App, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	return func(c echo.Context) error {
		returnURL := getReturnURL(&c, app.Config.FrontEndServer.URL)
		cookie, err := c.Cookie("browserToken")
		if err != nil || cookie.Value == "" {
			setErrorMessage(&c, "You are not logged in.")
			return c.Redirect(http.StatusSeeOther, returnURL)
		}

		var user User
		result := app.DB.First(&user, "browser_token = ?", cookie.Value)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				c.SetCookie(&http.Cookie{
					Name: "browserToken",
				})
				setErrorMessage(&c, "You are not logged in.")
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			return err
		}

		return f(c, &user)
	}
}

// GET /
func FrontRoot(app *App) func(c echo.Context) error {
	type rootContext struct {
		App            *App
		ErrorMessage   string
		SuccessMessage string
	}

	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "root", rootContext{
			App:            app,
			ErrorMessage:   lastErrorMessage(&c),
			SuccessMessage: lastSuccessMessage(&c),
		})
	}
}

// GET /registration
func FrontRegistration(app *App) func(c echo.Context) error {
	type rootContext struct {
		App            *App
		ErrorMessage   string
		SuccessMessage string
	}

	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "registration", rootContext{
			App:            app,
			ErrorMessage:   lastErrorMessage(&c),
			SuccessMessage: lastSuccessMessage(&c),
		})
	}
}

// GET /profile
func FrontProfile(app *App) func(c echo.Context) error {
	type profileContext struct {
		App            *App
		User           *User
		ErrorMessage   string
		SuccessMessage string
		SkinURL        *string
		CapeURL        *string
	}

	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
		var skinURL *string
		if user.SkinHash.Valid {
			url := SkinURL(app, user.SkinHash.String)
			skinURL = &url
		}

		var capeURL *string
		if user.CapeHash.Valid {
			url := CapeURL(app, user.CapeHash.String)
			capeURL = &url
		}
		return c.Render(http.StatusOK, "profile", profileContext{
			App:            app,
			User:           user,
			SkinURL:        skinURL,
			CapeURL:        capeURL,
			ErrorMessage:   lastErrorMessage(&c),
			SuccessMessage: lastSuccessMessage(&c),
		})
	})
}

// POST /update
func FrontUpdate(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
		returnURL := getReturnURL(&c, app.Config.FrontEndServer.URL+"/profile")

		playerName := c.FormValue("playerName")
		password := c.FormValue("password")
		preferredLanguage := c.FormValue("preferredLanguage")
		skinModel := c.FormValue("skinModel")
		skinURL := c.FormValue("skinUrl")
		capeURL := c.FormValue("capeUrl")

		if err := ValidatePlayerName(app, playerName); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid player name: %s", err))
			return c.Redirect(http.StatusSeeOther, returnURL)
		}
		user.PlayerName = playerName

		if !IsValidPreferredLanguage(preferredLanguage) {
			setErrorMessage(&c, "Invalid preferred language.")
			return c.Redirect(http.StatusSeeOther, returnURL)
		}
		user.PreferredLanguage = preferredLanguage

		if password != "" {
			if err := ValidatePassword(password); err != nil {
				setErrorMessage(&c, fmt.Sprintf("Invalid password: %s", err))
			}
			passwordSalt := make([]byte, 16)
			_, err := rand.Read(passwordSalt)
			if err != nil {
				return err
			}
			user.PasswordSalt = passwordSalt

			passwordHash, err := HashPassword(password, passwordSalt)
			if err != nil {
				return err
			}
			user.PasswordHash = passwordHash
		}

		if !IsValidSkinModel(skinModel) {
			return c.NoContent(http.StatusBadRequest)
		}
		user.SkinModel = skinModel

		skinFile, skinFileErr := c.FormFile("skinFile")
		if skinFileErr == nil {
			skinHandle, err := skinFile.Open()
			if err != nil {
				return err
			}
			defer skinHandle.Close()

			validSkinHandle, err := ValidateSkin(app, skinHandle)
			if err != nil {
				setErrorMessage(&c, fmt.Sprintf("Error using that skin: %s", err))
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			err = SetSkin(app, user, validSkinHandle)
			if err != nil {
				return err
			}
		} else if skinURL != "" {
			res, err := http.Get(skinURL)
			if err != nil {
				setErrorMessage(&c, "Couldn't download skin from that URL.")
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			defer res.Body.Close()

			validSkinHandle, err := ValidateSkin(app, res.Body)
			if err != nil {
				setErrorMessage(&c, fmt.Sprintf("Error using that skin: %s", err))
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			err = SetSkin(app, user, validSkinHandle)

			if err != nil {
				return nil
			}
		}

		capeFile, capeFileErr := c.FormFile("capeFile")
		if capeFileErr == nil {
			capeHandle, err := capeFile.Open()
			if err != nil {
				return err
			}
			defer capeHandle.Close()

			validCapeHandle, err := ValidateCape(app, capeHandle)
			if err != nil {
				setErrorMessage(&c, fmt.Sprintf("Error using that cape: %s", err))
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			err = SetCape(app, user, validCapeHandle)
			if err != nil {
				return err
			}
		} else if capeURL != "" {
			res, err := http.Get(capeURL)
			if err != nil {
				setErrorMessage(&c, "Couldn't download cape from that URL.")
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			defer res.Body.Close()

			validCapeHandle, err := ValidateCape(app, res.Body)
			if err != nil {
				setErrorMessage(&c, fmt.Sprintf("Error using that cape: %s", err))
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			err = SetCape(app, user, validCapeHandle)

			if err != nil {
				return nil
			}
		}

		err := app.DB.Save(&user).Error
		if err != nil {
			if IsErrorUniqueFailed(err) {
				setErrorMessage(&c, "That player name is taken.")
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			return err
		}

		setSuccessMessage(&c, "Changes saved.")
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /logout
func FrontLogout(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
		returnURL := app.Config.FrontEndServer.URL
		c.SetCookie(&http.Cookie{
			Name: "browserToken",
		})
		user.BrowserToken = MakeNullString(nil)
		app.DB.Save(user)
		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

func getChallenge(app *App, username string, token string) []byte {
	// This challenge is nice because:
	// - it doesn't depend on any serverside state
	// - an attacker can't use it to verify a different username, since hash
	// incorporates the username - an attacker can't generate their own
	// challenges, since the hash includes a hash of the instance's private key
	// - an attacker can't steal the skin mid-verification and register the
	// account themselves, since the hash incorporates a token known only to
	// the verifying browser
	challengeBytes := bytes.Join([][]byte{
		[]byte(username),
		*app.KeyB3Sum512,
		[]byte(token),
	}, []byte{})

	sum := blake3.Sum512(challengeBytes)
	return sum[:]
}

// GET /challenge-skin
func FrontChallengeSkin(app *App) func(c echo.Context) error {
	type verifySkinContext struct {
		App                  *App
		Username             string
		RegistrationProvider string
		SkinBase64           string
		SkinFilename         string
		ErrorMessage         string
		SuccessMessage       string
		ChallengeToken       string
	}

	verification_skin_file, err := os.Open(app.Constants.VerificationSkinPath)
	Check(err)

	verification_rgba, err := png.Decode(verification_skin_file)
	Check(err)

	verification_img, ok := verification_rgba.(*image.NRGBA)
	if !ok {
		log.Fatal("Invalid verification skin!")
	}

	return func(c echo.Context) error {
		returnURL := getReturnURL(&c, app.Config.FrontEndServer.URL+"/registration")

		username := c.QueryParam("username")
		if err := ValidateUsername(app, username); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid username: %s", err))
			return c.Redirect(http.StatusSeeOther, returnURL)
		}

		var challengeToken string
		cookie, err := c.Cookie("challengeToken")
		if err != nil || cookie.Value == "" {
			challengeToken, err = RandomHex(32)
			if err != nil {
				return err
			}
			c.SetCookie(&http.Cookie{
				Name:    "challengeToken",
				Value:   challengeToken,
				Expires: time.Now().Add(24 * time.Hour),
			})
		} else {
			challengeToken = cookie.Value
		}

		// challenge is a 512-bit, 64 byte checksum
		challenge := getChallenge(app, username, challengeToken)

		// Embed the challenge into a skin
		skinSize := 64
		img := image.NewNRGBA(image.Rectangle{image.Point{0, 0}, image.Point{skinSize, skinSize}})

		challengeByte := 0
		for y := 0; y < skinSize; y += 1 {
			for x := 0; x < skinSize; x += 1 {
				var col color.NRGBA
				if SKIN_WINDOW_Y_MIN <= y && y < SKIN_WINDOW_Y_MAX && SKIN_WINDOW_X_MIN <= x && x < SKIN_WINDOW_X_MAX {
					col = color.NRGBA{
						challenge[challengeByte],
						challenge[challengeByte+1],
						challenge[challengeByte+2],
						challenge[challengeByte+3],
					}
					challengeByte += 4
				} else {
					col = verification_img.At(x, y).(color.NRGBA)
				}
				img.SetNRGBA(x, y, col)
			}
		}

		var imgBuffer bytes.Buffer
		err = png.Encode(&imgBuffer, img)
		if err != nil {
			return err
		}

		skinBase64 := base64.StdEncoding.EncodeToString(imgBuffer.Bytes())
		return c.Render(http.StatusOK, "challenge-skin", verifySkinContext{
			App:            app,
			Username:       username,
			SkinBase64:     skinBase64,
			SkinFilename:   username + "-challenge.png",
			ErrorMessage:   lastErrorMessage(&c),
			SuccessMessage: lastSuccessMessage(&c),
			ChallengeToken: challengeToken,
		})
	}
}

// type registrationUsernameToIDResponse struct {
// 	Name string `json:"name"`
// 	ID   string `json:"id"`
// }

type proxiedAccountDetails struct {
	UUID string
}

func validateChallenge(app *App, username string, challengeToken string) (*proxiedAccountDetails, error) {
	base, err := url.Parse(app.Config.RegistrationExistingPlayer.AccountURL)
	if err != nil {
		return nil, err
	}
	base.Path += "/users/profiles/minecraft/" + username

	res, err := http.Get(base.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log
		return nil, errors.New("registration server returned error")
	}

	var idRes playerNameToUUIDResponse
	err = json.NewDecoder(res.Body).Decode(&idRes)
	if err != nil {
		return nil, err
	}

	base, err = url.Parse(app.Config.RegistrationExistingPlayer.SessionURL)
	if err != nil {
		return nil, err
	}
	base.Path += "/session/minecraft/profile/" + idRes.ID

	res, err = http.Get(base.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log
		return nil, errors.New("Registration server returned error")
	}

	var profileRes profileResponse
	err = json.NewDecoder(res.Body).Decode(&profileRes)
	if err != nil {
		return nil, err
	}
	id := profileRes.ID
	accountUUID, err := IDToUUID(id)
	if err != nil {
		return nil, err
	}

	details := proxiedAccountDetails{
		UUID: accountUUID,
	}
	if !app.Config.RegistrationExistingPlayer.RequireSkinVerification {
		return &details, nil
	}

	for _, property := range profileRes.Properties {
		if property.Name == "textures" {
			textureJSON, err := base64.StdEncoding.DecodeString(property.Value)
			if err != nil {
				return nil, err
			}

			var texture texturesValue
			err = json.Unmarshal(textureJSON, &texture)
			if err != nil {
				return nil, err
			}

			res, err = http.Get(texture.Textures.Skin.URL)
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()

			rgba_img, err := png.Decode(res.Body)
			if err != nil {
				return nil, err
			}
			img, ok := rgba_img.(*image.NRGBA)
			if !ok {
				return nil, errors.New("Invalid image")
			}

			challenge := make([]byte, 64)
			challengeByte := 0
			for y := SKIN_WINDOW_Y_MIN; y < SKIN_WINDOW_Y_MAX; y += 1 {
				for x := SKIN_WINDOW_X_MIN; x < SKIN_WINDOW_X_MAX; x += 1 {
					c := img.NRGBAAt(x, y)
					challenge[challengeByte] = c.R
					challenge[challengeByte+1] = c.G
					challenge[challengeByte+2] = c.B
					challenge[challengeByte+3] = c.A

					challengeByte += 4
				}
			}

			correctChallenge := getChallenge(app, username, challengeToken)

			if !bytes.Equal(challenge, correctChallenge) {
				return nil, errors.New("invalid skin")
			}

			if err != nil {
				return nil, err
			}

			return &details, nil
		}
	}

	return nil, errors.New("registration server didn't return textures")
}

// POST /register
func FrontRegister(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		returnURL := app.Config.FrontEndServer.URL + "/profile"
		failureURL := getReturnURL(&c, app.Config.FrontEndServer.URL+"/registration")

		username := c.FormValue("username")
		password := c.FormValue("password")
		chosenUUID := c.FormValue("uuid")
		challengeToken := c.FormValue("challengeToken")

		if err := ValidateUsername(app, username); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid username: %s", err))
			return c.Redirect(http.StatusSeeOther, failureURL)
		}
		if err := ValidatePassword(password); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid password: %s", err))
			return c.Redirect(http.StatusSeeOther, failureURL)
		}

		var accountUUID string
		if challengeToken != "" {
			// Registration from an existing account on another server
			if !app.Config.RegistrationExistingPlayer.Allow {
				setErrorMessage(&c, "Registration from an existing account is not allowed.")
				return c.Redirect(http.StatusSeeOther, failureURL)
			}

			// Verify skin challenge
			details, err := validateChallenge(app, username, challengeToken)
			if err != nil {
				var message string
				if app.Config.RegistrationExistingPlayer.RequireSkinVerification {
					message = fmt.Sprintf("Couldn't verify your skin, maybe try again: %s", err)
				} else {
					message = fmt.Sprintf("Couldn't find your account, maybe try again: %s", err)
				}
				setErrorMessage(&c, message)
				return c.Redirect(http.StatusSeeOther, failureURL)
			}
			accountUUID = details.UUID
		} else {
			// New player registration

			if chosenUUID == "" {
				accountUUID = uuid.New().String()
			} else {
				if !app.Config.RegistrationNewPlayer.AllowChoosingUUID {
					setErrorMessage(&c, "Choosing a UUID is not allowed.")
					return c.Redirect(http.StatusSeeOther, failureURL)
				}
				chosenUUIDStruct, err := uuid.Parse(chosenUUID)
				if err != nil {
					message := fmt.Sprintf("Invalid UUID: %s", err)
					setErrorMessage(&c, message)
					return c.Redirect(http.StatusSeeOther, failureURL)
				}
				accountUUID = chosenUUIDStruct.String()
			}

		}

		passwordSalt := make([]byte, 16)
		_, err := rand.Read(passwordSalt)
		if err != nil {
			return err
		}

		passwordHash, err := HashPassword(password, passwordSalt)
		if err != nil {
			return err
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}

		user := User{
			UUID:              accountUUID,
			Username:          username,
			PasswordSalt:      passwordSalt,
			PasswordHash:      passwordHash,
			TokenPairs:        []TokenPair{},
			PlayerName:        username,
			PreferredLanguage: "en",
			SkinModel:         SkinModelClassic,
			BrowserToken:      MakeNullString(&browserToken),
		}

		result := app.DB.Create(&user)
		if result.Error != nil {
			if IsErrorUniqueFailedField(result.Error, "users.username") ||
				IsErrorUniqueFailedField(result.Error, "users.player_name") {
				setErrorMessage(&c, "That username is taken.")
				return c.Redirect(http.StatusSeeOther, failureURL)
			} else if IsErrorUniqueFailedField(result.Error, "users.uuid") {
				setErrorMessage(&c, "That UUID is taken.")
				return c.Redirect(http.StatusSeeOther, failureURL)
			}
			return result.Error
		}

		c.SetCookie(&http.Cookie{
			Name:    "browserToken",
			Value:   browserToken,
			Expires: time.Now().Add(24 * time.Hour),
		})

		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

// POST /login
func FrontLogin(app *App) func(c echo.Context) error {
	successURL := app.Config.FrontEndServer.URL + "/profile"
	return func(c echo.Context) error {
		failureURL := getReturnURL(&c, app.Config.FrontEndServer.URL)

		username := c.FormValue("username")
		password := c.FormValue("password")

		if AnonymousLoginEligible(app, username) {
			setErrorMessage(&c, "Anonymous accounts cannot access the web interface.")
			return c.Redirect(http.StatusSeeOther, failureURL)
		}

		var user User
		result := app.DB.First(&user, "username = ?", username)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				setErrorMessage(&c, "User not found!")
				return c.Redirect(http.StatusSeeOther, failureURL)
			}
			return result.Error
		}

		passwordHash, err := HashPassword(password, user.PasswordSalt)
		if err != nil {
			return err
		}

		if !bytes.Equal(passwordHash, user.PasswordHash) {
			setErrorMessage(&c, "Incorrect password!")
			return c.Redirect(http.StatusSeeOther, failureURL)
		}

		browserToken, err := RandomHex(32)
		if err != nil {
			return err
		}

		c.SetCookie(&http.Cookie{
			Name:    "browserToken",
			Value:   browserToken,
			Expires: time.Now().Add(24 * time.Hour),
		})

		user.BrowserToken = MakeNullString(&browserToken)
		app.DB.Save(&user)

		return c.Redirect(http.StatusSeeOther, successURL)
	}
}

// POST /delete-account
func FrontDeleteAccount(app *App) func(c echo.Context) error {
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
		returnURL := app.Config.FrontEndServer.URL
		c.SetCookie(&http.Cookie{
			Name: "browserToken",
		})

		oldSkinHash := UnmakeNullString(&user.SkinHash)
		oldCapeHash := UnmakeNullString(&user.CapeHash)
		app.DB.Delete(&user)

		if oldSkinHash != nil {
			err := DeleteSkin(app, *oldSkinHash)
			if err != nil {
				return err
			}
		}

		if oldCapeHash != nil {
			err := DeleteCape(app, *oldCapeHash)
			if err != nil {
				return err
			}
		}

		setSuccessMessage(&c, "Account deleted")

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}
