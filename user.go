package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"gorm.io/gorm"
	"io"
	"net/http"
	"time"
)

// Must be in a region of the skin that supports translucency
const SKIN_WINDOW_X_MIN = 40
const SKIN_WINDOW_X_MAX = 48
const SKIN_WINDOW_Y_MIN = 9
const SKIN_WINDOW_Y_MAX = 11

var InviteNotFoundError error = NewBadRequestUserError("Invite not found.")
var InviteMissingError error = NewBadRequestUserError("Registration requires an invite.")

func (app *App) ValidateIDToken(idToken string) (*OIDCProvider, oidc.IDTokenClaims, error) {
	var claims oidc.IDTokenClaims
	_, err := oidc.ParseToken(idToken, &claims)
	if err != nil {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError("Invalid ID token from %s", claims.Issuer)
	}

	oidcProvider, ok := app.OIDCProvidersByIssuer[claims.Issuer]
	if !ok {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError("Unknown OIDC issuer: %s", claims.Issuer)
	}

	verifier := oidcProvider.RelyingParty.IDTokenVerifier()
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](context.Background(), idToken, verifier)
	if err != nil {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError("Invalid ID token from %s", claims.Issuer)
	}

	return oidcProvider, claims, nil
}

func (app *App) CreateUser(
	caller *User,
	username string,
	password *string,
	idTokens []string,
	isAdmin bool,
	isLocked bool,
	inviteCode *string,
	preferredLanguage *string,
	playerName *string,
	chosenUUID *string,
	existingPlayer bool,
	challengeToken *string,
	fallbackPlayer *string,
	maxPlayerCount *int,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	capeReader *io.Reader,
	capeURL *string,
) (User, error) {
	callerIsAdmin := caller != nil && caller.IsAdmin

	userUUID := uuid.New().String()

	if password != nil {
		if !app.Config.AllowPasswordLogin {
			return User{}, NewBadRequestUserError("Password registration is not allowed.")
		}
		if err := app.ValidatePassword(*password); err != nil {
			return User{}, NewBadRequestUserError("Invalid password: %s", err)
		}
	}

	if password != nil && len(idTokens) > 0 {
		return User{}, NewBadRequestUserError("Can't specify both a password and an idToken.")
	}
	if password == nil && len(idTokens) == 0 {
		return User{}, NewBadRequestUserError("Must specify either a password xor an idToken.")
	}

	oidcIdentities := make([]UserOIDCIdentity, 0, len(idTokens))
	usernameMatchesEmail := false
	for _, idToken := range idTokens {
		_, claims, err := app.ValidateIDToken(idToken)
		if err != nil {
			return User{}, err
		}

		usernameMatchesEmail = usernameMatchesEmail || (claims.Email == username)

		oidcIdentities = append(oidcIdentities, UserOIDCIdentity{
			UserUUID: userUUID,
			Issuer:   claims.Issuer,
			Subject:  claims.Subject,
		})
	}
	if len(idTokens) > 0 && !usernameMatchesEmail {
		return User{}, NewBadRequestUserError("No ID token matches that username.")
	}

	if !usernameMatchesEmail {
		if err := app.ValidateUsername(username); err != nil {
			return User{}, NewBadRequestUserError("Invalid username: %s", err)
		}
	}

	if playerName == nil {
		playerName = &username
	} else {
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
			if app.Config.ImportExistingPlayer.RequireSkinVerification {
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

	passwordSalt := []byte{}
	passwordHash := []byte{}
	if password != nil {
		passwordSalt = make([]byte, 16)
		_, err := rand.Read(passwordSalt)
		if err != nil {
			return User{}, err
		}
		passwordHash, err = HashPassword(*password, passwordSalt)
		if err != nil {
			return User{}, err
		}
	}

	if isAdmin && !callerIsAdmin {
		return User{}, NewBadRequestUserError("Cannot make a new admin user without having admin privileges yourself.")
	}

	if isLocked && !callerIsAdmin {
		return User{}, NewBadRequestUserError("Cannot make a new locked user without admin privileges.")
	}

	maxPlayerCountInt := Constants.MaxPlayerCountUseDefault
	if maxPlayerCount != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError("Cannot set a max player count without admin privileges.")
		}
		err := app.ValidateMaxPlayerCount(*maxPlayerCount)
		if err != nil {
			return User{}, NewBadRequestUserError("Invalid max player count: %s", err)
		}
		maxPlayerCountInt = *maxPlayerCount
	}

	apiToken, err := MakeAPIToken()
	if err != nil {
		return User{}, err
	}

	minecraftToken, err := MakeMinecraftToken()
	if err != nil {
		return User{}, err
	}

	user := User{
		IsAdmin:           Contains(app.Config.DefaultAdmins, username) || isAdmin,
		IsLocked:          isLocked,
		UUID:              userUUID,
		Username:          username,
		PasswordSalt:      passwordSalt,
		PasswordHash:      passwordHash,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		MaxPlayerCount:    maxPlayerCountInt,
		APIToken:          apiToken,
		MinecraftToken:    minecraftToken,
		OIDCIdentities:    oidcIdentities,
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

var PasswordLoginNotAllowedError error = NewUserError(http.StatusUnauthorized, "Password login is not allowed.")

func (app *App) AuthenticateUserForMigration(username string, password string) (User, error) {
	var user User
	result := app.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return User{}, NewUserError(http.StatusUnauthorized, "User not found.")
		}
		return User{}, result.Error
	}

	if len(user.OIDCIdentities) > 0 {
		return User{}, PasswordLoginNotAllowedError
	}

	passwordHash, err := HashPassword(password, user.PasswordSalt)
	if err != nil {
		return User{}, err
	}

	if !bytes.Equal(passwordHash, user.PasswordHash) {
		return User{}, NewUserError(http.StatusUnauthorized, "Incorrect password.")
	}

	return user, nil
}

func (app *App) AuthenticateUser(username string, password string) (User, error) {
	var user User
	result := app.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return User{}, NewUserError(http.StatusUnauthorized, "User not found.")
		}
		return User{}, result.Error
	}

	if !app.Config.AllowPasswordLogin || len(user.OIDCIdentities) > 0 {
		return User{}, PasswordLoginNotAllowedError
	}

	passwordHash, err := HashPassword(password, user.PasswordSalt)
	if err != nil {
		return User{}, err
	}

	if !bytes.Equal(passwordHash, user.PasswordHash) {
		return User{}, NewUserError(http.StatusUnauthorized, "Incorrect password.")
	}

	if user.IsLocked {
		return User{}, NewUserError(http.StatusForbidden, "User is locked.")
	}

	return user, nil
}

func (app *App) UpdateUser(
	db *gorm.DB,
	caller *User,
	user User,
	password *string,
	isAdmin *bool,
	isLocked *bool,
	resetAPIToken bool,
	resetMinecraftToken bool,
	preferredLanguage *string,
	maxPlayerCount *int,
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
		if !(*isAdmin) && app.IsDefaultAdmin(&user) {
			return User{}, NewBadRequestUserError("Cannot revoke admin status of a default admin.")
		}
		user.IsAdmin = *isAdmin
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

	if resetMinecraftToken {
		minecraftToken, err := MakeMinecraftToken()
		if err != nil {
			return User{}, err
		}
		user.MinecraftToken = minecraftToken
	}

	if maxPlayerCount != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError("Cannot set a max player count without admin privileges.")
		}
		err := app.ValidateMaxPlayerCount(*maxPlayerCount)
		if err != nil {
			return User{}, NewBadRequestUserError("Invalid max player count: %s", err)
		}
		user.MaxPlayerCount = *maxPlayerCount
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if isLocked != nil {
			if !callerIsAdmin {
				return NewBadRequestUserError("Cannot change locked status of user without having admin privileges yourself.")
			}
			err := app.SetIsLocked(tx, &user, *isLocked)
			if err != nil {
				return err
			}
		}

		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return User{}, err
	}

	return user, nil
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
	if err := db.Save(user).Error; err != nil {
		return err
	}
	return nil
}

func (app *App) DeleteUser(caller *User, user *User) error {
	if !caller.IsAdmin && caller.UUID != user.UUID {
		return NewUserError(http.StatusForbidden, "You are not an admin.")
	}

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

func (app *App) CreateOIDCIdentity(
	caller *User,
	userUUID string,
	issuer string,
	subject string,
) (UserOIDCIdentity, error) {
	if caller == nil {
		return UserOIDCIdentity{}, NewBadRequestUserError("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && !callerIsAdmin {
		return UserOIDCIdentity{}, NewBadRequestUserError("Can't link an OIDC account for another user unless you're an admin.")
	}

	var user User
	if err := app.DB.First(&user, "uuid = ?", userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return UserOIDCIdentity{}, NewBadRequestUserError("User not found.")
		}
		return UserOIDCIdentity{}, err
	}

	userOIDCIdentity := UserOIDCIdentity{
		UserUUID: userUUID,
		Issuer:   issuer,
		Subject:  subject,
	}

	err := app.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&userOIDCIdentity).Error; err != nil {
			if IsErrorUniqueFailedField(err, "user_oidc_identities.issuer, user_oidc_identities.subject") {
				provider, ok := app.OIDCProvidersByIssuer[issuer]
				if !ok {
					return fmt.Errorf("Unknown OIDC provider: %s", issuer)
				}
				return NewBadRequestUserError("That %s account is already linked to another user.", provider.Config.Name)
			}
			if IsErrorUniqueFailedField(err, "user_oidc_identities.issuer") {
				provider, ok := app.OIDCProvidersByIssuer[issuer]
				if !ok {
					return fmt.Errorf("Unknown OIDC provider: %s", issuer)
				}
				return NewBadRequestUserError("That user is already linked to a %s account.", provider.Config.Name)
			}
			return err
		}
		user.OIDCIdentities = append(user.OIDCIdentities, userOIDCIdentity)
		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return UserOIDCIdentity{}, err
	}

	return userOIDCIdentity, nil
}

func (app *App) DeleteOIDCIdentity(
	caller *User,
	userUUID string,
	providerName string,
) error {
	if caller == nil {
		return NewBadRequestUserError("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && callerIsAdmin {
		return NewBadRequestUserError("Can't unlink an OIDC account for another user unless you're an admin.")
	}

	provider, ok := app.OIDCProvidersByName[providerName]
	if !ok {
		return NewBadRequestUserError("Unknown OIDC provider: %s", providerName)
	}

	return app.DB.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&UserOIDCIdentity{}).Where("user_uuid = ?", userUUID).Count(&count).Error; err != nil {
			return err
		}

		if count <= 1 {
			return NewBadRequestUserError("Can't remove the last linked OIDC account.")
		}

		var userOIDCIdentity UserOIDCIdentity
		if err := tx.First(&userOIDCIdentity, "user_uuid = ? AND issuer = ?", userUUID, provider.Config.Issuer).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return NewBadRequestUserError("No linked %s account found.", providerName)
			}
			return err
		}

		if err := tx.Delete(&userOIDCIdentity).Error; err != nil {
			return err
		}
		return nil
	})
}
