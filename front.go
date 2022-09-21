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
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"time"
)

// https://echo.labstack.com/guide/templates/
// https://stackoverflow.com/questions/36617949/how-to-use-base-template-file-for-golang-html-template/69244593#69244593
type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, err := template.New("").ParseFiles("view/layout.html", "view/" + name + ".html")
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

// Read and clear the error message cookie
func lastErrorMessage(c *echo.Context) string {
	cookie, err := (*c).Cookie("errorMessage")
	if err != nil || cookie.Value == "" {
		return ""
	}
	setErrorMessage(c, "")
	return cookie.Value
}

// Authenticate a user using the `browserToken` cookie, and call `f` with a
// reference to the user
func withBrowserAuthentication(app *App, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("browserToken")
		if err != nil || cookie.Value == "" {
			return c.Redirect(http.StatusSeeOther, app.Config.FrontEndServer.URL)
		}

		var user User
		result := app.DB.First(&user, "browser_token = ?", cookie.Value)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				c.SetCookie(&http.Cookie{
					Name: "browserToken",
				})
				return c.Redirect(http.StatusSeeOther, app.Config.FrontEndServer.URL)
			}
			return err
		}

		return f(c, &user)
	}
}

// GET /
func FrontRoot(app *App) func(c echo.Context) error {
	type rootContext struct {
		Config       *Config
		ErrorMessage string
	}

	type profileContext struct {
		Config       *Config
		User         *User
		ErrorMessage string
		SkinURL      *string
		CapeURL      *string
	}

	profile := func(c echo.Context, user *User) error {
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
			Config:       app.Config,
			User:         user,
			SkinURL:      skinURL,
			CapeURL:      capeURL,
			ErrorMessage: lastErrorMessage(&c),
		})
	}

	return func(c echo.Context) error {
		cookie, err := c.Cookie("browserToken")
		if err != nil || cookie.Value == "" {
			// register/sign in page
			return c.Render(http.StatusOK, "root", rootContext{
				Config:       app.Config,
				ErrorMessage: lastErrorMessage(&c),
			})
		}
		return withBrowserAuthentication(app, profile)(c)
	}
}

// POST /update
func FrontUpdate(app *App) func(c echo.Context) error {
	returnURL := app.Config.FrontEndServer.URL
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
		playerName := c.FormValue("playerName")
		password := c.FormValue("password")
		preferredLanguage := c.FormValue("preferredLanguage")
		skinModel := c.FormValue("skinModel")
		skinURL := c.FormValue("skinUrl")
		capeURL := c.FormValue("capeUrl")

		if err := ValidatePlayerName(playerName); err != nil {
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

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}

// POST /logout
func FrontLogout(app *App) func(c echo.Context) error {
	returnURL := app.Config.FrontEndServer.URL
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
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
		*app.KeyB3Sum,
		[]byte(token),
	}, []byte{})

	sum := blake3.Sum512(challengeBytes)
	return sum[:]
}

// GET /challenge-skin
func FrontChallengeSkin(app *App) func(c echo.Context) error {
	returnURL := app.Config.FrontEndServer.URL
	type verifySkinContext struct {
		Config         *Config
		Username       string
		SkinBase64     string
		SkinFilename   string
		ErrorMessage   string
		ChallengeToken string
	}
	return func(c echo.Context) error {
		username := c.QueryParam("username")

		if err := ValidateUsername(username); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid username: %s", err))
			return c.Redirect(http.StatusSeeOther, returnURL)
		}

		challengeToken, err := RandomHex(32)
		challengeToken = "a"
		if err != nil {
			return err
		}

		// challenge is a 512-bit, 64 byte checksum
		challenge := getChallenge(app, username, challengeToken)

		// Embed the challenge into a skin
		skinSize := 64
		img := image.NewNRGBA(image.Rectangle{image.Point{0, 0}, image.Point{skinSize, skinSize}})

		challengeByte := 0
		for y := 0; y < 2; y += 1 {
			for x := 40; x < 48; x += 1 {
				col := color.NRGBA{
					challenge[challengeByte],
					challenge[challengeByte+1],
					challenge[challengeByte+2],
					challenge[challengeByte+3],
				}
				challengeByte += 4
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
			Config:         app.Config,
			Username:       username,
			SkinBase64:     skinBase64,
			SkinFilename:   username + "-challenge.png",
			ErrorMessage:   lastErrorMessage(&c),
			ChallengeToken: challengeToken,
		})
	}
}

type registrationUsernameToIDResponse struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func validateChallenge(app *App, username string, challengeToken string) error {
	base, err := url.Parse(app.Config.RegistrationProxy.ServicesURL)
	if err != nil {
		return err
	}
	base.Path += "/users/profiles/minecraft/" + username

	res, err := http.Get(base.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log
		return errors.New("registration server returned error")
	}

	var idRes playerNameToUUIDResponse
	err = json.NewDecoder(res.Body).Decode(&idRes)
	if err != nil {
		return err
	}

	base, err = url.Parse(app.Config.RegistrationProxy.SessionURL)
	if err != nil {
		return err
	}
	base.Path += "/session/minecraft/profile/" + idRes.ID

	res, err = http.Get(base.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log
		return errors.New("registration server returned error")
	}

	var profileRes profileResponse
	err = json.NewDecoder(res.Body).Decode(&profileRes)
	if err != nil {
		return err
	}

	for _, property := range profileRes.Properties {
		if property.Name == "textures" {
			textureJSON, err := base64.StdEncoding.DecodeString(property.Value)
			if err != nil {
				return err
			}

			var texture texturesValue
			err = json.Unmarshal(textureJSON, &texture)
			if err != nil {
				return err
			}

			res, err = http.Get(texture.Textures.Skin.URL)
			if err != nil {
				return err
			}
			defer res.Body.Close()

			rgba_img, err := png.Decode(res.Body)
			if err != nil {
				return err
			}
			img, ok := rgba_img.(*image.NRGBA)
			if !ok {
				return errors.New("Invalid image")
			}

			challenge := make([]byte, 64)
			challengeByte := 0
			for y := 0; y < 2; y += 1 {
				for x := 40; x < 48; x += 1 {
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
				return errors.New("invalid skin")
			}

			return nil
		}
	}

	return errors.New("registration server didn't return textures")
}

// POST /register
func FrontRegister(app *App) func(c echo.Context) error {
	returnURL := app.Config.FrontEndServer.URL
	return func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		challengeToken := c.FormValue("challengeToken")

		if err := ValidateUsername(username); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid username: %s", err))
			return c.Redirect(http.StatusSeeOther, returnURL)
		}
		if err := ValidatePassword(password); err != nil {
			setErrorMessage(&c, fmt.Sprintf("Invalid password: %s", err))
			return c.Redirect(http.StatusSeeOther, returnURL)
		}

		if challengeToken != "" {
			// Verify skin challenge
			err := validateChallenge(app, username, challengeToken)
			if err != nil {
				message := fmt.Sprintf("Invalid skin: %s", err)
				setErrorMessage(&c, message)
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			return c.String(http.StatusOK, "welcome!")
		} else {
			// standalone registration
		}

		uuid := uuid.New()

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
			UUID:              uuid.String(),
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
			if IsErrorUniqueFailed(err) {
				setErrorMessage(&c, "That username is taken.")
				return c.Redirect(http.StatusSeeOther, returnURL)
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
	returnURL := app.Config.FrontEndServer.URL
	return func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")

		var user User
		result := app.DB.First(&user, "username = ?", username)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				setErrorMessage(&c, "User not found!")
				return c.Redirect(http.StatusSeeOther, returnURL)
			}
			return result.Error
		}

		passwordHash, err := HashPassword(password, user.PasswordSalt)
		if err != nil {
			return err
		}

		if !bytes.Equal(passwordHash, user.PasswordHash) {
			setErrorMessage(&c, "Incorrect password!")
			return c.Redirect(http.StatusSeeOther, returnURL)
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

		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

// POST /delete-account
func FrontDeleteAccount(app *App) func(c echo.Context) error {
	returnURL := app.Config.FrontEndServer.URL
	return withBrowserAuthentication(app, func(c echo.Context, user *User) error {
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

		return c.Redirect(http.StatusSeeOther, returnURL)
	})
}
