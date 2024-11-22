package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"time"
)

// Must be in a region of the skin that supports translucency
const SKIN_WINDOW_X_MIN = 40
const SKIN_WINDOW_X_MAX = 48
const SKIN_WINDOW_Y_MIN = 9
const SKIN_WINDOW_Y_MAX = 11

var InviteNotFoundError error = NewBadRequestUserError("Invite not found.")
var InviteMissingError error = NewBadRequestUserError("Registration requires an invite.")

func (app *App) CreateUser(
	caller *User,
	username string,
	password string,
	isAdmin bool,
	isLocked bool,
	chosenUUID *string,
	existingPlayer bool,
	challengeToken *string,
	inviteCode *string,
	playerName *string,
	fallbackPlayer *string,
	preferredLanguage *string,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	capeReader *io.Reader,
	capeURL *string,
) (User, error) {
	callerIsAdmin := caller != nil && caller.IsAdmin

	if err := app.ValidateUsername(username); err != nil {
		return User{}, NewBadRequestUserError("Invalid username: %s", err)
	}
	if err := app.ValidatePassword(password); err != nil {
		return User{}, NewBadRequestUserError("Invalid password: %s", err)
	}
	if playerName == nil {
		playerName = &username
	} else {
		if *playerName != username && !app.Config.AllowChangingPlayerName && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Choosing a player name different from your username is not allowed.")
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError("Invalid player name: %s", err)
		}
	}

	if preferredLanguage == nil {
		preferredLanguage = &app.Config.DefaultPreferredLanguage
	}
	if !IsValidPreferredLanguage(*preferredLanguage) {
		return User{}, NewBadRequestUserError("Invalid preferred language.")
	}

	getInvite := func(requireInvite bool) (*Invite, error) {
		var invite Invite
		if inviteCode == nil {
			if requireInvite && !callerIsAdmin {
				return nil, InviteMissingError
			}
			return nil, nil
		} else {
			result := app.DB.First(&invite, "code = ?", *inviteCode)
			if result.Error != nil {
				if errors.Is(result.Error, gorm.ErrRecordNotFound) {
					return nil, InviteNotFoundError
				}
				return nil, result.Error
			}
			return &invite, nil
		}
	}

	var accountUUID string
	var invite *Invite
	if existingPlayer {
		// Existing player registration
		if !app.Config.RegistrationExistingPlayer.Allow && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Registration from an existing account is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationExistingPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID != nil {
			return User{}, NewBadRequestUserError("Can't register from an existing account AND choose a UUID.")
		}

		details, err := app.ValidateChallenge(*playerName, challengeToken)
		if err != nil {
			if app.Config.RegistrationExistingPlayer.RequireSkinVerification {
				return User{}, NewBadRequestUserError("Couldn't verify your skin, maybe try again: %s", err)
			} else {
				return User{}, NewBadRequestUserError("Couldn't find your account, maybe try again: %s", err)
			}
		}
		playerName = &details.Username

		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError("Invalid player name: %s", err)
		}
		accountUUID = details.UUID
	} else {
		// New player registration
		if !app.Config.RegistrationNewPlayer.Allow && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Registration without some existing account is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationNewPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID == nil {
			accountUUID = uuid.New().String()
		} else {
			if !app.Config.RegistrationNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return User{}, NewBadRequestUserError("Choosing a UUID is not allowed.")
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
			if err != nil {
				return User{}, NewBadRequestUserError("Invalid UUID: %s", err)
			}
			accountUUID = chosenUUIDStruct.String()
		}
	}

	passwordSalt := make([]byte, 16)
	_, err := rand.Read(passwordSalt)
	if err != nil {
		return User{}, err
	}

	passwordHash, err := HashPassword(password, passwordSalt)
	if err != nil {
		return User{}, err
	}

	if isAdmin && !callerIsAdmin {
		return User{}, NewBadRequestUserError("Cannot make a new admin user without having admin privileges yourself.")
	}

	if isLocked && !callerIsAdmin {
		return User{}, NewBadRequestUserError("Cannot make a new locked user without admin privileges.")
	}

	offlineUUID, err := OfflineUUID(username)
	if err != nil {
		return User{}, err
	}

	if fallbackPlayer == nil {
		fallbackPlayer = &accountUUID
	}
	if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
		return User{}, NewBadRequestUserError("Invalid fallback player: %s", err)
	}

	apiToken, err := MakeAPIToken()
	if err != nil {
		return User{}, err
	}

	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return User{}, NewBadRequestUserError("Invalid skin model.")
	}

	var skinHash *string
	var skinBuf *bytes.Buffer
	if skinReader != nil || skinURL != nil {
		if !app.Config.AllowSkins && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Setting a skin is not allowed.")
		}
		if skinReader != nil && skinURL != nil {
			return User{}, NewBadRequestUserError("Can't specify both a skin file and a skin URL.")
		}
		if skinURL != nil {
			res, err := MakeHTTPClient().Get(*skinURL)
			if err != nil {
				return User{}, NewBadRequestUserError("Couldn't download skin from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			skinReader = &bodyReader
		}
		validSkinHandle, err := app.ValidateSkin(*skinReader)
		if err != nil {
			return User{}, NewBadRequestUserError("Error using that skin: %s", err)
		}
		var hash string
		skinBuf, hash, err = app.ReadTexture(validSkinHandle)
		if err != nil {
			return User{}, err
		}
		skinHash = &hash
	}

	var capeHash *string
	var capeBuf *bytes.Buffer
	if capeReader != nil || capeURL != nil {
		if !app.Config.AllowCapes && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Setting a cape is not allowed.")
		}
		if capeReader != nil && capeURL != nil {
			return User{}, NewBadRequestUserError("Can't specify both a cape file and a cape URL.")
		}
		if capeURL != nil {
			res, err := MakeHTTPClient().Get(*capeURL)
			if err != nil {
				return User{}, NewBadRequestUserError("Couldn't download cape from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			capeReader = &bodyReader
		}
		validCapeHandle, err := app.ValidateCape(*capeReader)
		if err != nil {
			return User{}, NewBadRequestUserError("Error using that cape: %s", err)
		}
		var hash string
		capeBuf, hash, err = app.ReadTexture(validCapeHandle)
		if err != nil {
			return User{}, err
		}
		capeHash = &hash
	}

	user := User{
		IsAdmin:           Contains(app.Config.DefaultAdmins, username) || isAdmin,
		IsLocked:          isLocked,
		UUID:              accountUUID,
		Username:          username,
		PasswordSalt:      passwordSalt,
		PasswordHash:      passwordHash,
		Clients:           []Client{},
		PlayerName:        *playerName,
		OfflineUUID:       offlineUUID,
		FallbackPlayer:    *fallbackPlayer,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		SkinModel:         *skinModel,
		SkinHash:          MakeNullString(skinHash),
		CapeHash:          MakeNullString(capeHash),
		APIToken:          apiToken,
		CreatedAt:         time.Now(),
		NameLastChangedAt: time.Now(),
	}

	tx := app.DB.Begin()
	defer tx.Rollback()

	result := tx.Create(&user)
	if result.Error != nil {
		if IsErrorUniqueFailedField(result.Error, "users.username") ||
			IsErrorUniqueFailedField(result.Error, "users.player_name") {
			return User{}, NewBadRequestUserError("That username is taken.")
		} else if IsErrorUniqueFailedField(result.Error, "users.uuid") {
			return User{}, NewBadRequestUserError("That UUID is taken.")
		}
		return User{}, result.Error
	}

	if invite != nil {
		result = tx.Delete(invite)
		if result.Error != nil {
			return User{}, result.Error
		}
	}

	result = tx.Commit()
	if result.Error != nil {
		return User{}, result.Error
	}

	if skinHash != nil {
		err = app.WriteSkin(*skinHash, skinBuf)
		if err != nil {
			return user, NewBadRequestUserError("Error saving the skin.")
		}
	}

	if capeHash != nil {
		err = app.WriteCape(*capeHash, capeBuf)
		if err != nil {
			return user, NewBadRequestUserError("Error saving the cape.")
		}
	}

	return user, nil
}

func (app *App) UpdateUser(
	caller *User,
	user User,
	password *string,
	isAdmin *bool,
	isLocked *bool,
	playerName *string,
	fallbackPlayer *string,
	resetAPIToken bool,
	preferredLanguage *string,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	deleteSkin bool,
	capeReader *io.Reader,
	capeURL *string,
	deleteCape bool,
) (User, error) {
	if caller == nil {
		return User{}, NewBadRequestUserError("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if user.UUID != caller.UUID && !callerIsAdmin {
		return User{}, NewBadRequestUserError("You are not an admin.")
	}

	if password != nil {
		if err := app.ValidatePassword(*password); err != nil {
			return User{}, NewBadRequestUserError("Invalid password: %s", err)
		}
		passwordSalt := make([]byte, 16)
		_, err := rand.Read(passwordSalt)
		if err != nil {
			return User{}, err
		}
		user.PasswordSalt = passwordSalt

		passwordHash, err := HashPassword(*password, passwordSalt)
		if err != nil {
			return User{}, err
		}
		user.PasswordHash = passwordHash
	}

	if isAdmin != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError("Cannot change admin status of user without having admin privileges yourself.")
		}
		user.IsAdmin = *isAdmin
	}

	if isLocked != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError("Cannot change locked status of user without having admin privileges yourself.")
		}
		user.IsLocked = *isLocked
	}

	if playerName != nil && *playerName != user.PlayerName {
		if !app.Config.AllowChangingPlayerName && !user.IsAdmin {
			return User{}, NewBadRequestUserError("Changing your player name is not allowed.")
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError("Invalid player name: %s", err)
		}
		offlineUUID, err := OfflineUUID(*playerName)
		if err != nil {
			return User{}, err
		}
		user.PlayerName = *playerName
		user.OfflineUUID = offlineUUID
		user.NameLastChangedAt = time.Now()
	}

	if fallbackPlayer != nil && *fallbackPlayer != user.FallbackPlayer {
		if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
			return User{}, NewBadRequestUserError("Invalid fallback player: %s", err)
		}
		user.FallbackPlayer = *fallbackPlayer
	}

	if preferredLanguage != nil {
		if !IsValidPreferredLanguage(*preferredLanguage) {
			return User{}, NewBadRequestUserError("Invalid preferred language.")
		}
		user.PreferredLanguage = *preferredLanguage
	}

	if resetAPIToken {
		apiToken, err := MakeAPIToken()
		if err != nil {
			return User{}, err
		}
		user.APIToken = apiToken
	}

	if skinModel != nil {
		if !IsValidSkinModel(*skinModel) {
			return User{}, NewBadRequestUserError("Invalid skin model.")
		}
		user.SkinModel = *skinModel
	}

	// Skin and cape updates are done as follows:
	// 1. Validate with ValidateSkin/ValidateCape
	// 2. Read the texture into memory and hash it with ReadTexture
	// 3. Update the database
	// 4. If the database updated successfully:
	//    - Acquire a lock to the texture file
	//    - If the texture file doesn't exist, write it to disk
	//    - Delete the old texture if it's unused
	//
	// Any update should happen first to the DB, then to the filesystem. We
	// don't attempt to roll back changes to the DB if we fail to write to
	// the filesystem.

	var skinBuf *bytes.Buffer
	oldSkinHash := UnmakeNullString(&user.SkinHash)

	if skinReader != nil || skinURL != nil {
		// The user is setting a new skin
		if !app.Config.AllowSkins && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Setting a skin is not allowed.")
		}

		if skinReader != nil && skinURL != nil {
			return User{}, NewBadRequestUserError("Can't specify both a skin file and a skin URL.")
		}

		if skinURL != nil {
			if !app.Config.AllowTextureFromURL && !callerIsAdmin {
				return User{}, NewBadRequestUserError("Setting a skin from a URL is not allowed.")
			}
			res, err := MakeHTTPClient().Get(*skinURL)
			if err != nil {
				return User{}, NewBadRequestUserError("Couldn't download skin from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			skinReader = &bodyReader
		}
		validSkinHandle, err := app.ValidateSkin(*skinReader)
		if err != nil {
			return User{}, NewBadRequestUserError("Error using that skin: %s", err)
		}
		var hash string
		skinBuf, hash, err = app.ReadTexture(validSkinHandle)
		if err != nil {
			return User{}, err
		}
		user.SkinHash = MakeNullString(&hash)
	} else if deleteSkin {
		user.SkinHash = MakeNullString(nil)
	}

	var capeBuf *bytes.Buffer
	oldCapeHash := UnmakeNullString(&user.CapeHash)
	if capeReader != nil || capeURL != nil {
		if !app.Config.AllowCapes && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Setting a cape is not allowed.")
		}
		if capeReader != nil && capeURL != nil {
			return User{}, NewBadRequestUserError("Can't specify both a cape file and a cape URL.")
		}
		if capeURL != nil {
			if !app.Config.AllowTextureFromURL && !callerIsAdmin {
				return User{}, NewBadRequestUserError("Setting a cape from a URL is not allowed.")
			}
			res, err := MakeHTTPClient().Get(*capeURL)
			if err != nil {
				return User{}, NewBadRequestUserError("Couldn't download cape from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			capeReader = &bodyReader
		}
		validCapeHandle, err := app.ValidateCape(*capeReader)
		if err != nil {
			return User{}, NewBadRequestUserError("Error using that cape: %s", err)
		}
		var hash string
		capeBuf, hash, err = app.ReadTexture(validCapeHandle)
		if err != nil {
			return User{}, err
		}
		user.CapeHash = MakeNullString(&hash)
	} else if deleteCape {
		user.CapeHash = MakeNullString(nil)
	}

	newSkinHash := UnmakeNullString(&user.SkinHash)
	newCapeHash := UnmakeNullString(&user.CapeHash)

	err := app.DB.Save(&user).Error
	if err != nil {
		if IsErrorUniqueFailed(err) {
			return User{}, NewBadRequestUserError("That player name is taken.")
		}
		return User{}, err
	}

	if !PtrEquals(oldSkinHash, newSkinHash) {
		if newSkinHash != nil {
			err = app.WriteSkin(*newSkinHash, skinBuf)
			if err != nil {
				return User{}, NewBadRequestUserError("Error saving the skin.")
			}
		}

		err = app.DeleteSkinIfUnused(oldSkinHash)
		if err != nil {
			return User{}, err
		}
	}
	if !PtrEquals(oldCapeHash, newCapeHash) {
		if newCapeHash != nil {
			err = app.WriteCape(*newCapeHash, capeBuf)
			if err != nil {
				return User{}, NewBadRequestUserError("Error saving the cape.")
			}
		}

		err = app.DeleteCapeIfUnused(oldCapeHash)
		if err != nil {
			return User{}, err
		}
	}

	return user, nil
}

type proxiedAccountDetails struct {
	Username string
	UUID     string
}

func (app *App) GetChallenge(username string, token string) []byte {
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
		app.KeyB3Sum512,
		[]byte(token),
	}, []byte{})

	sum := blake3.Sum512(challengeBytes)
	return sum[:]
}

func (app *App) ValidateChallenge(username string, challengeToken *string) (*proxiedAccountDetails, error) {
	base, err := url.Parse(app.Config.RegistrationExistingPlayer.AccountURL)
	if err != nil {
		return nil, err
	}
	base.Path, err = url.JoinPath(base.Path, "users/profiles/minecraft/"+username)
	if err != nil {
		return nil, err
	}

	res, err := MakeHTTPClient().Get(base.String())
	if err != nil {
		log.Printf("Couldn't access registration server at %s: %s\n", base.String(), err)
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Printf("Request to registration server at %s resulted in status code %d\n", base.String(), res.StatusCode)
		return nil, errors.New("registration server returned error")
	}

	var idRes playerNameToUUIDResponse
	err = json.NewDecoder(res.Body).Decode(&idRes)
	if err != nil {
		return nil, err
	}

	base, err = url.Parse(app.Config.RegistrationExistingPlayer.SessionURL)
	if err != nil {
		return nil, fmt.Errorf("Invalid SessionURL %s: %s", app.Config.RegistrationExistingPlayer.SessionURL, err)
	}
	base.Path, err = url.JoinPath(base.Path, "session/minecraft/profile/"+idRes.ID)
	if err != nil {
		return nil, err
	}

	res, err = MakeHTTPClient().Get(base.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Printf("Request to registration server at %s resulted in status code %d\n", base.String(), res.StatusCode)
		return nil, errors.New("registration server returned error")
	}

	var profileRes SessionProfileResponse
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
		Username: profileRes.Name,
		UUID:     accountUUID,
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

			if texture.Textures.Skin == nil {
				return nil, errors.New("player does not have a skin")
			}
			res, err = MakeHTTPClient().Get(texture.Textures.Skin.URL)
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
				return nil, errors.New("invalid image")
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

			if challengeToken == nil {
				return nil, errors.New("missing challenge token")
			}
			correctChallenge := app.GetChallenge(username, *challengeToken)

			if !bytes.Equal(challenge, correctChallenge) {
				return nil, errors.New("skin does not match")
			}

			if err != nil {
				return nil, err
			}

			return &details, nil
		}
	}

	return nil, errors.New("registration server didn't return textures")
}

func MakeChallengeToken() (string, error) {
	return RandomHex(16)
}

func (app *App) GetChallengeSkin(username string, challengeToken string) ([]byte, error) {
	if err := app.ValidateUsername(username); err != nil {
		return nil, NewBadRequestUserError("Invalid username: %s", err)
	}

	// challenge is a 512-bit, 64 byte checksum
	challenge := app.GetChallenge(username, challengeToken)

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
				col = app.VerificationSkinTemplate.At(x, y).(color.NRGBA)
			}
			img.SetNRGBA(x, y, col)
		}
	}

	var imgBuffer bytes.Buffer
	err := png.Encode(&imgBuffer, img)
	if err != nil {
		return nil, err
	}

	return imgBuffer.Bytes(), nil
}

func (app *App) InvalidateUser(db *gorm.DB, user *User) error {
	result := db.Model(Client{}).Where("user_uuid = ?", user.UUID).Update("version", gorm.Expr("version + ?", 1))
	return result.Error
}

func (app *App) SetIsLocked(db *gorm.DB, user *User, isLocked bool) error {
	user.IsLocked = isLocked
	if isLocked {
		user.BrowserToken = MakeNullString(nil)
		err := app.InvalidateUser(db, user)
		if err != nil {
			return err
		}
	}
	return nil
}

func (app *App) DeleteUser(user *User) error {
	oldSkinHash := UnmakeNullString(&user.SkinHash)
	oldCapeHash := UnmakeNullString(&user.CapeHash)
	err := app.DB.Select("Clients").Delete(&user).Error
	if err != nil {
		return err
	}

	err = app.DeleteSkinIfUnused(oldSkinHash)
	if err != nil {
		return err
	}

	err = app.DeleteCapeIfUnused(oldCapeHash)
	if err != nil {
		return err
	}

	return nil
}
