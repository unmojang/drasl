package main

import (
	"crypto/rand"
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"io"
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
	inviteCode *string,
	preferredLanguage *string,
	playerName *string,
	chosenUUID *string,
	existingPlayer bool,
	challengeToken *string,
	fallbackPlayer *string,
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

	var invite *Invite
	var playerUUID string
	if existingPlayer {
		// Existing player registration
		if !app.Config.RegistrationExistingPlayer.Allow && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Registration from an existing player is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationExistingPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError("Invalid player name: %s", err)
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
		playerUUID = details.UUID
	} else {
		// New player registration
		if !app.Config.RegistrationNewPlayer.Allow && !callerIsAdmin {
			return User{}, NewBadRequestUserError("Registration without some existing player is not allowed.")
		}

		var err error
		invite, err = getInvite(app.Config.RegistrationNewPlayer.RequireInvite)
		if err != nil {
			return User{}, err
		}

		if chosenUUID == nil {
			playerUUID = uuid.New().String()
		} else {
			if !app.Config.RegistrationNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return User{}, NewBadRequestUserError("Choosing a UUID is not allowed.")
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
			if err != nil {
				return User{}, NewBadRequestUserError("Invalid UUID: %s", err)
			}
			playerUUID = chosenUUIDStruct.String()
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

	apiToken, err := MakeAPIToken()
	if err != nil {
		return User{}, err
	}

	user := User{
		IsAdmin:           Contains(app.Config.DefaultAdmins, username) || isAdmin,
		IsLocked:          isLocked,
		UUID:              uuid.New().String(),
		Username:          username,
		PasswordSalt:      passwordSalt,
		PasswordHash:      passwordHash,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		APIToken:          apiToken,
		MaxPlayerCount:    Constants.MaxPlayerCountUseDefault,
	}

	// Player
	offlineUUID, err := OfflineUUID(*playerName)
	if err != nil {
		return User{}, err
	}

	if fallbackPlayer == nil {
		fallbackPlayer = &playerUUID
	}
	if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
		return User{}, NewBadRequestUserError("Invalid fallback player: %s", err)
	}
	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return User{}, NewBadRequestUserError("Invalid skin model.")
	}

	skinHash, skinBuf, err := app.getTexture("skin", caller, skinReader, skinURL)
	if err != nil {
		return User{}, err
	}

	capeHash, capeBuf, err := app.getTexture("cape", caller, capeReader, capeURL)
	if err != nil {
		return User{}, err
	}

	tx := app.DB.Begin()
	defer tx.Rollback()

	if err := tx.Create(&user).Error; err != nil {
		if IsErrorUniqueFailedField(err, "users.username") {
			return User{}, NewBadRequestUserError("That username is taken.")
		} else if IsErrorUsernameTakenByPlayerName(err) {
			return User{}, NewBadRequestUserError("That username is in use as the name of another user's player.")
		} else {
			return User{}, err
		}
	}

	player := Player{
		UUID:              playerUUID,
		UserUUID:          user.UUID,
		Clients:           []Client{},
		Name:              *playerName,
		OfflineUUID:       offlineUUID,
		FallbackPlayer:    *fallbackPlayer,
		SkinModel:         *skinModel,
		SkinHash:          MakeNullString(skinHash),
		CapeHash:          MakeNullString(capeHash),
		CreatedAt:         time.Now(),
		NameLastChangedAt: time.Now(),
	}
	user.Players = append(user.Players, player)

	if err := tx.Create(&player).Error; err != nil {
		if IsErrorUniqueFailedField(err, "players.name") {
			return User{}, NewBadRequestUserError("That player name is taken.")
		} else if IsErrorUniqueFailedField(err, "players.uuid") {
			return User{}, NewBadRequestUserError("That UUID is taken.")
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return User{}, NewBadRequestUserError("That player name is in use as another user's username.")
		} else {
			return User{}, err
		}
	}

	if invite != nil {
		if err := tx.Delete(invite).Error; err != nil {
			return User{}, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return User{}, err
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
	resetAPIToken bool,
	preferredLanguage *string,
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

	if err := app.DB.Save(&user).Error; err != nil {
		return User{}, err
	}

	return user, nil
}

func (app *App) SetIsLocked(db *gorm.DB, user *User, isLocked bool) error {
	user.IsLocked = isLocked
	if isLocked {
		user.BrowserToken = MakeNullString(nil)
		for _, player := range user.Players {
			err := app.InvalidatePlayer(db, &player)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (app *App) DeleteUser(user *User) error {
	oldSkinHashes := make([]*string, 0, len(user.Players))
	oldCapeHashes := make([]*string, 0, len(user.Players))

	var players []Player
	if err := app.DB.Where("user_uuid = ?", user.UUID).Find(&players).Error; err != nil {
		return err
	}
	for _, player := range players {
		oldSkinHashes = append(oldSkinHashes, UnmakeNullString(&player.SkinHash))
		oldCapeHashes = append(oldCapeHashes, UnmakeNullString(&player.CapeHash))
	}

	if err := app.DB.Delete(user).Error; err != nil {
		return err
	}

	for _, oldSkinHash := range oldSkinHashes {
		err := app.DeleteSkinIfUnused(oldSkinHash)
		if err != nil {
			return err
		}
	}

	for _, oldCapeHash := range oldCapeHashes {
		err := app.DeleteCapeIfUnused(oldCapeHash)
		if err != nil {
			return err
		}
	}

	return nil
}
