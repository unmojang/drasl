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
		return User{}, fmt.Errorf("Invalid username: %s", err)
	}
	if err := app.ValidatePassword(password); err != nil {
		return User{}, fmt.Errorf("Invalid password: %s", err)
	}
	if playerName == nil {
		playerName = &username
	} else {
		if *playerName != username && !app.Config.AllowChangingPlayerName && !callerIsAdmin {
			return User{}, errors.New("Choosing a player name different from your username is not allowed.")
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, fmt.Errorf("Invalid player name: %s", err)
		}
	}

	if preferredLanguage == nil {
		preferredLanguage = &app.Config.DefaultPreferredLanguage
	}
	if !IsValidPreferredLanguage(*preferredLanguage) {
		return User{}, errors.New("Invalid preferred language.")
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
			return User{}, errors.New("Registration from an existing account is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationExistingPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID != nil {
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

		if chosenUUID == nil {
			accountUUID = uuid.New().String()
		} else {
			if !app.Config.RegistrationNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return User{}, errors.New("Choosing a UUID is not allowed.")
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
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

	if isAdmin && !callerIsAdmin {
		return User{}, errors.New("Cannot make a new admin user without having admin privileges yourself.")
	}

	if isLocked && !callerIsAdmin {
		return User{}, errors.New("Cannot make a new locked user without admin privileges.")
	}

	offlineUUID, err := OfflineUUID(username)
	if err != nil {
		return User{}, err
	}

	if fallbackPlayer == nil {
		fallbackPlayer = &accountUUID
	}
	if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
		return User{}, fmt.Errorf("Invalid fallback player: %s", err)
	}

	apiToken, err := MakeAPIToken()
	if err != nil {
		return User{}, err
	}

	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return User{}, errors.New("Invalid skin model.")
	}

	var skinHash *string
	var skinBuf *bytes.Buffer
	if skinReader != nil || skinURL != nil {
		if !app.Config.AllowSkins && !callerIsAdmin {
			return User{}, errors.New("Setting a skin is not allowed.")
		}
		if skinReader != nil && skinURL != nil {
			return User{}, errors.New("Can't specify both a skin file and a skin URL.")
		}
		if skinURL != nil {
			res, err := MakeHTTPClient().Get(*skinURL)
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
	if capeReader != nil || capeURL != nil {
		if !app.Config.AllowCapes && !callerIsAdmin {
			return User{}, errors.New("Setting a cape is not allowed.")
		}
		if capeReader != nil && capeURL != nil {
			return User{}, errors.New("Can't specify both a cape file and a cape URL.")
		}
		if capeURL != nil {
			res, err := MakeHTTPClient().Get(*capeURL)
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
		return User{}, errors.New("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if user.UUID != caller.UUID && !callerIsAdmin {
		return User{}, errors.New("You are not an admin.")
	}

	if password != nil {
		if err := app.ValidatePassword(*password); err != nil {
			return User{}, fmt.Errorf("Invalid password: %s", err)
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
			return User{}, errors.New("Cannot change admin status of user without having admin privileges yourself.")
		}
		user.IsAdmin = *isAdmin
	}

	if isLocked != nil {
		if !callerIsAdmin {
			return User{}, errors.New("Cannot change locked status of user without having admin privileges yourself.")
		}
		user.IsLocked = *isLocked
	}

	if playerName != nil && *playerName != user.PlayerName {
		if !app.Config.AllowChangingPlayerName && !user.IsAdmin {
			return User{}, errors.New("Changing your player name is not allowed.")
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, fmt.Errorf("Invalid player name: %s", err)
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
			return User{}, fmt.Errorf("Invalid fallback player: %s", err)
		}
	}

	if preferredLanguage != nil {
		if !IsValidPreferredLanguage(*preferredLanguage) {
			return User{}, errors.New("Invalid preferred language.")
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
			return User{}, errors.New("Invalid skin model.")
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
			return User{}, errors.New("Setting a skin is not allowed.")
		}

		if skinReader != nil && skinURL != nil {
			return User{}, errors.New("Can't specify both a skin file and a skin URL.")
		}

		if skinURL != nil {
			res, err := MakeHTTPClient().Get(*skinURL)
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
		user.SkinHash = MakeNullString(&hash)
	} else if deleteSkin {
		user.SkinHash = MakeNullString(nil)
	}

	var capeBuf *bytes.Buffer
	oldCapeHash := UnmakeNullString(&user.CapeHash)
	if capeReader != nil || capeURL != nil {
		if !app.Config.AllowCapes && !callerIsAdmin {
			return User{}, errors.New("Setting a cape is not allowed.")
		}
		if capeReader != nil && capeURL != nil {
			return User{}, errors.New("Can't specify both a cape file and a cape URL.")
		}
		if capeURL != nil {
			res, err := MakeHTTPClient().Get(*capeURL)
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
		user.CapeHash = MakeNullString(&hash)
	} else if deleteCape {
		user.CapeHash = MakeNullString(nil)
	}

	newSkinHash := UnmakeNullString(&user.SkinHash)
	newCapeHash := UnmakeNullString(&user.CapeHash)

	err := app.DB.Save(&user).Error
	if err != nil {
		if IsErrorUniqueFailed(err) {
			return User{}, errors.New("That player name is taken.")
		}
		return User{}, err
	}

	if !PtrEquals(oldSkinHash, newSkinHash) {
		if newSkinHash != nil {
			err = app.WriteSkin(*newSkinHash, skinBuf)
			if err != nil {
				return User{}, errors.New("Error saving the skin.")
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
				return User{}, errors.New("Error saving the cape.")
			}
		}

		err = app.DeleteCapeIfUnused(oldCapeHash)
		if err != nil {
			return User{}, err
		}
	}

	return user, nil
}
