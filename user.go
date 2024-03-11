package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"io"
	"math/rand"
	"time"
)

var InviteNotFoundError error = errors.New("Invite not found.")
var InviteMissingError error = errors.New("Registration requires an invite.")

func (app *App) CreateUser(
	caller *User,
	username string,
	password string,
	chosenUUID string,
	existingPlayer bool,
	challengeToken string,
	inviteCode string,
	playerName string,
	fallbackPlayer string,
	preferredLanguage string,
	skinModel string,
	skinReader *io.Reader,
	skinURL string,
	capeReader *io.Reader,
	capeURL string,
) (User, error) {
	callerIsAdmin := caller != nil && caller.IsAdmin

	if err := app.ValidateUsername(username); err != nil {
		return User{}, fmt.Errorf("Invalid username: %s", err)
	}
	if err := app.ValidatePassword(password); err != nil {
		return User{}, fmt.Errorf("Invalid password: %s", err)
	}

	if preferredLanguage == "" {
		preferredLanguage = app.Config.DefaultPreferredLanguage
	}
	if !IsValidPreferredLanguage(preferredLanguage) {
		return User{}, errors.New("Invalid preferred language.")
	}

	getInvite := func(requireInvite bool) (*Invite, error) {
		var invite Invite
		if inviteCode == "" {
			if requireInvite && !callerIsAdmin {
				return nil, InviteMissingError
			}
			return nil, nil
		} else {
			result := app.DB.First(&invite, "code = ?", inviteCode)
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
			return User{}, errors.New("Registration from an existing account is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationExistingPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID != "" {
			return User{}, errors.New("Can't register from an existing account AND choose a UUID.")
		}

		details, err := app.ValidateChallenge(username, challengeToken)
		if err != nil {
			if app.Config.RegistrationExistingPlayer.RequireSkinVerification {
				return User{}, fmt.Errorf("Couldn't verify your skin, maybe try again: %s", err)
			} else {
				return User{}, fmt.Errorf("Couldn't find your account, maybe try again: %s", err)
			}
		}
		username = details.Username

		if err := app.ValidateUsername(username); err != nil {
			return User{}, fmt.Errorf("Invalid username: %s", err)
		}
		accountUUID = details.UUID
	} else {
		// New player registration
		if !app.Config.RegistrationNewPlayer.Allow && !callerIsAdmin {
			return User{}, errors.New("Registration without some existing account is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationNewPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID == "" {
			accountUUID = uuid.New().String()
		} else {
			if !app.Config.RegistrationNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return User{}, errors.New("Choosing a UUID is not allowed.")
			}
			chosenUUIDStruct, err := uuid.Parse(chosenUUID)
			if err != nil {
				return User{}, fmt.Errorf("Invalid UUID: %s", err)
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

	offlineUUID, err := OfflineUUID(username)
	if err != nil {
		return User{}, err
	}

	if fallbackPlayer == "" {
		fallbackPlayer = accountUUID
	}
	if err := app.ValidatePlayerNameOrUUID(fallbackPlayer); err != nil {
		return User{}, fmt.Errorf("Invalid fallback player: %s", err)
	}

	apiToken, err := MakeAPIToken()

	if skinModel == "" {
		skinModel = SkinModelClassic
	}
	if !IsValidSkinModel(skinModel) {
		return User{}, fmt.Errorf("Invalid skin model: %s", skinModel)
	}

	var skinHash *string
	var skinBuf *bytes.Buffer
	if skinReader != nil || skinURL != "" {
		if skinReader != nil && skinURL != "" {
			return User{}, errors.New("Can't specify both a skin file and a skin URL.")
		}
		if !app.Config.AllowSkins && !callerIsAdmin {
			return User{}, errors.New("Setting a skin is not allowed.")
		}
		if skinURL != "" {
			res, err := MakeHTTPClient().Get(skinURL)
			if err != nil {
				return User{}, fmt.Errorf("Couldn't download skin from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			skinReader = &bodyReader
		}
		validSkinHandle, err := app.ValidateSkin(*skinReader)
		if err != nil {
			return User{}, fmt.Errorf("Error using that skin: %s", err)
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
	if capeReader != nil || capeURL != "" {
		if capeReader != nil && capeURL != "" {
			return User{}, errors.New("Can't specify both a cape file and a cape URL.")
		}
		if !app.Config.AllowCapes && !callerIsAdmin {
			return User{}, errors.New("Setting a cape is not allowed.")
		}
		if capeURL != "" {
			res, err := MakeHTTPClient().Get(capeURL)
			if err != nil {
				return User{}, fmt.Errorf("Couldn't download cape from that URL: %s", err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			capeReader = &bodyReader
		}
		validCapeHandle, err := app.ValidateCape(*capeReader)
		if err != nil {
			return User{}, fmt.Errorf("Error using that cape: %s", err)
		}
		var hash string
		capeBuf, hash, err = app.ReadTexture(validCapeHandle)
		if err != nil {
			return User{}, err
		}
		capeHash = &hash
	}

	user := User{
		IsAdmin:           Contains(app.Config.DefaultAdmins, username),
		UUID:              accountUUID,
		Username:          username,
		PasswordSalt:      passwordSalt,
		PasswordHash:      passwordHash,
		Clients:           []Client{},
		PlayerName:        username,
		OfflineUUID:       offlineUUID,
		FallbackPlayer:    fallbackPlayer,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		SkinModel:         skinModel,
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
			return User{}, errors.New("That username is taken.")
		} else if IsErrorUniqueFailedField(result.Error, "users.uuid") {
			return User{}, errors.New("That UUID is taken.")
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
			return user, errors.New("Error saving the skin.")
		}
	}

	if capeHash != nil {
		err = app.WriteCape(*capeHash, capeBuf)
		if err != nil {
			return user, errors.New("Error saving the cape.")
		}
	}

	return user, nil
}
