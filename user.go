package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/samber/mo"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"gorm.io/gorm"
)

// Must be in a region of the skin that supports translucency
const SKIN_WINDOW_X_MIN = 40
const SKIN_WINDOW_X_MAX = 48
const SKIN_WINDOW_Y_MIN = 9
const SKIN_WINDOW_Y_MAX = 11

var InviteNotFoundError error = NewBadRequestUserError(Tr("Invite not found."))
var InviteMissingError error = NewBadRequestUserError(Tr("Registration requires an invite."))

func (app *App) ValidateIDToken(idToken, nonce string) (*OIDCProvider, oidc.IDTokenClaims, error) {
	var claims oidc.IDTokenClaims
	_, err := oidc.ParseToken(idToken, &claims)
	if err != nil {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError(Tr("Invalid ID token from %s", claims.Issuer))
	}

	oidcProvider, ok := app.OIDCProvidersByIssuer[claims.Issuer]
	if !ok {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError(Tr("Unknown OIDC issuer: %s", claims.Issuer))
	}

	verifier := oidcProvider.RelyingParty.IDTokenVerifier()
	ctx := context.WithValue(context.Background(), CONTEXT_KEY_NONCE, nonce)
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, idToken, verifier)
	if err != nil {
		return nil, oidc.IDTokenClaims{}, NewBadRequestUserError(Tr("Invalid ID token from %s", claims.Issuer))
	}

	return oidcProvider, claims, nil
}

type OIDCIdentitySpec struct {
	Issuer  string
	Subject string
}

func (app *App) CreateUser(
	caller *User,
	username string,
	password *string,
	// You must verify that the caller owns these OIDC identities (or is an admin).
	oidcIdentitySpecs PotentiallyInsecure[[]OIDCIdentitySpec],
	isAdmin bool,
	isDisabled bool,
	chatMode *ChatMode,
	inviteCode *string,
	preferredLanguage *string,
	playerName *string,
	chosenUUID *string,
	fallbackAPIServerNickname *string,
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

	if err := app.ValidateUsername(username); err != nil {
		return User{}, NewBadRequestUserError(Tr("Invalid username: %s", err))
	}

	if password == nil && len(oidcIdentitySpecs.Value) == 0 {
		return User{}, NewBadRequestUserError(Tr("Must specify either a password or an OIDC identity."))
	}

	if password != nil {
		if !app.Config.AllowPasswordLogin {
			return User{}, NewBadRequestUserError(Tr("Password registration is not allowed."))
		}
		if err := app.ValidatePassword(*password); err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid password: %s", err))
		}
	}

	var invite mo.Option[Invite]
	if inviteCode != nil {
		var inviteStruct Invite
		result := app.DB.First(&inviteStruct, "code = ?", *inviteCode)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return User{}, InviteNotFoundError
			} else {
				return User{}, result.Error
			}
		} else {
			invite = mo.Some(inviteStruct)
		}
	}

	oidcIdentities := make([]UserOIDCIdentity, 0, len(oidcIdentitySpecs.Value))
	for _, oidcIdentitySpec := range oidcIdentitySpecs.Value {
		provider, ok := app.OIDCProvidersByIssuer[oidcIdentitySpec.Issuer]
		if !ok {
			return User{}, NewBadRequestUserError(Tr("Unknown OIDC provider: %s", oidcIdentitySpec.Issuer))
		}
		if oidcIdentitySpec.Subject == "" {
			return User{}, NewBadRequestUserError(Tr("OIDC subject for provider %s can't be blank.", provider.Config.Issuer))
		}
		oidcIdentities = append(oidcIdentities, UserOIDCIdentity{
			UserUUID: userUUID,
			Issuer:   provider.Config.Issuer,
			Subject:  oidcIdentitySpec.Subject,
		})
	}

	if playerName == nil {
		playerName = &username
	}
	if err := app.ValidatePlayerName(*playerName); err != nil {
		return User{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
	}

	if preferredLanguage == nil {
		preferredLanguage = &app.Config.DefaultPreferredLanguage
	}
	if !IsValidPreferredLanguage(*preferredLanguage) {
		return User{}, NewBadRequestUserError(Tr("Invalid preferred language."))
	}

	var playerUUID string
	if fallbackAPIServerNickname != nil {
		// Existing player registration
		var requireSkinVerification bool
		var requireInvite bool

		if len(oidcIdentitySpecs.Value) > 0 {
			// OIDC registration
			issuer := oidcIdentitySpecs.Value[0].Issuer
			provider, ok := app.OIDCProvidersByIssuer[issuer]
			if !ok {
				return User{}, NewBadRequestUserError(Tr("Unknown OIDC provider: %s", issuer))
			}
			found := false
			for _, importExistingPlayerConfig := range provider.Config.ImportExistingPlayer {
				if importExistingPlayerConfig.FallbackAPIServerNickname == *fallbackAPIServerNickname {
					requireSkinVerification = importExistingPlayerConfig.RequireSkinVerification
					requireInvite = importExistingPlayerConfig.RequireInvite
					found = true
					break
				}
			}
			if !found && !callerIsAdmin {
				return User{}, NewBadRequestUserError(Tr("Registration from an existing player via %s is not allowed.", *fallbackAPIServerNickname))
			}
		} else {
			// Password registration
			found := false
			for _, importExistingPlayerConfig := range app.Config.RegistrationUsernamePassword.ImportExistingPlayer {
				if importExistingPlayerConfig.FallbackAPIServerNickname == *fallbackAPIServerNickname {
					requireSkinVerification = importExistingPlayerConfig.RequireSkinVerification
					requireInvite = importExistingPlayerConfig.RequireInvite
					found = true
					break
				}
			}
			if !found && !callerIsAdmin {
				return User{}, NewBadRequestUserError(Tr("Registration from an existing player via %s is not allowed.", *fallbackAPIServerNickname))
			}
		}

		if !callerIsAdmin && invite.IsAbsent() && requireInvite {
			return User{}, InviteMissingError
		}

		fallbackAPIServer := app.FallbackAPIServers[*fallbackAPIServerNickname]
		if fallbackAPIServer == nil {
			return User{}, NewBadRequestUserError(Tr("Unknown fallback API server: %s", *fallbackAPIServerNickname))
		}

		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
		}

		details, err := app.ValidateChallenge(fallbackAPIServer, *playerName, challengeToken, requireSkinVerification && !callerIsAdmin)
		if err != nil {
			if requireSkinVerification {
				return User{}, NewBadRequestUserError(Tr("Couldn't verify your skin, maybe try again: %s", err))
			} else {
				return User{}, NewBadRequestUserError(Tr("Couldn't find your account, maybe try again: %s", err))
			}
		}

		playerName = &details.Username
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
		}
		playerUUID = details.UUID
	} else {
		// New player registration
		var createNewPlayerConfig regCreateNewPlayerConfig
		if len(oidcIdentitySpecs.Value) > 0 {
			issuer := oidcIdentitySpecs.Value[0].Issuer
			provider, ok := app.OIDCProvidersByIssuer[issuer]
			if !ok {
				return User{}, NewBadRequestUserError(Tr("Unknown OIDC provider: %s", issuer))
			}
			createNewPlayerConfig = provider.Config.CreateNewPlayer
		} else {
			createNewPlayerConfig = app.Config.RegistrationUsernamePassword.CreateNewPlayer
		}

		if !createNewPlayerConfig.Allow && !callerIsAdmin {
			return User{}, NewBadRequestUserError(Tr("Registration without some existing player is not allowed."))
		}

		if !callerIsAdmin && invite.IsAbsent() && createNewPlayerConfig.RequireInvite {
			return User{}, InviteMissingError
		}

		if chosenUUID == nil {
			var err error
			playerUUID, err = app.NewPlayerUUID(*playerName)
			if err != nil {
				return User{}, err
			}
		} else {
			if !createNewPlayerConfig.AllowChoosingUUID && !callerIsAdmin {
				return User{}, NewBadRequestUserError(Tr("Choosing a UUID is not allowed."))
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
			if err != nil {
				return User{}, NewBadRequestUserError(Tr("Invalid UUID: %s", err))
			}
			playerUUID = chosenUUIDStruct.String()
		}
	}
	if err := app.EnsureNameAllowed(*playerName); err != nil {
		return User{}, err
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
		return User{}, NewBadRequestUserError(Tr("Cannot make a new admin user without having admin privileges yourself."))
	}

	if isDisabled && !callerIsAdmin {
		return User{}, NewBadRequestUserError(Tr("Cannot make a new disabled user without admin privileges."))
	}
	chatModeValue := ChatModeEnabled
	if chatMode != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError(Tr("Cannot set chat mode without admin privileges."))
		}
		if !IsValidChatMode(*chatMode) {
			return User{}, NewBadRequestUserError(Tr("Invalid chat mode."))
		}
		chatModeValue = *chatMode
	}

	maxPlayerCountInt := Constants.MaxPlayerCountUseDefault
	if maxPlayerCount != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError(Tr("Cannot set a max player count without admin privileges."))
		}
		err := app.ValidateMaxPlayerCount(*maxPlayerCount)
		if err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid max player count: %s", err))
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
		IsDisabled:        isDisabled,
		ChatMode:          chatModeValue,
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
		return User{}, NewBadRequestUserError(Tr("Invalid fallback player: %s", err))
	}
	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return User{}, NewBadRequestUserError(Tr("Invalid skin model."))
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
			return User{}, NewBadRequestUserError(Tr("That username is taken."))
		} else if IsErrorUsernameTakenByPlayerName(err) {
			return User{}, NewBadRequestUserError(Tr("That username is in use as the name of another user's player."))
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
			return User{}, NewBadRequestUserError(Tr("That player name is taken."))
		} else if IsErrorUniqueFailedField(err, "players.uuid") {
			return User{}, NewBadRequestUserError(Tr("That UUID is taken."))
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return User{}, NewBadRequestUserError(Tr("That player name is in use as another user's username."))
		} else {
			return User{}, err
		}
	}

	if i, ok := invite.Get(); ok {
		if err := tx.Delete(i).Error; err != nil {
			return User{}, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return User{}, err
	}

	if skinHash != nil {
		err = app.WriteSkin(*skinHash, skinBuf)
		if err != nil {
			return user, NewBadRequestUserError(Tr("Error saving the skin."))
		}
	}

	if capeHash != nil {
		err = app.WriteCape(*capeHash, capeBuf)
		if err != nil {
			return user, NewBadRequestUserError(Tr("Error saving the cape."))
		}
	}

	return user, nil
}

var PasswordLoginNotAllowedError error = NewUserErrorWithCode(http.StatusUnauthorized, Tr("Password login is not allowed."))

func (app *App) AuthenticateUserForMigration(username string, password string) (User, error) {
	var user User
	result := app.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return User{}, NewUserErrorWithCode(http.StatusUnauthorized, Tr("User not found."))
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

	if subtle.ConstantTimeCompare(passwordHash, user.PasswordHash) != 1 {
		return User{}, NewUserErrorWithCode(http.StatusUnauthorized, Tr("Incorrect password."))
	}

	return user, nil
}

func (app *App) AuthenticateUser(username string, password string) (User, error) {
	var user User
	result := app.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return User{}, NewUserErrorWithCode(http.StatusUnauthorized, Tr("User not found."))
		}
		return User{}, result.Error
	}

	if user.IsDisabled {
		return User{}, NewUserErrorWithCode(http.StatusForbidden, Tr("User is disabled."))
	}

	if !app.Config.AllowPasswordLogin || len(user.OIDCIdentities) > 0 {
		return User{}, PasswordLoginNotAllowedError
	}

	passwordHash, err := HashPassword(password, user.PasswordSalt)
	if err != nil {
		return User{}, err
	}

	if subtle.ConstantTimeCompare(passwordHash, user.PasswordHash) != 1 {
		return User{}, NewUserErrorWithCode(http.StatusUnauthorized, Tr("Incorrect password."))
	}

	return user, nil
}

func (app *App) UpdateUser(
	db *gorm.DB,
	caller *User,
	user User,
	password *string,
	isAdmin *bool,
	isDisabled *bool,
	chatMode *ChatMode,
	resetAPIToken bool,
	resetMinecraftToken bool,
	preferredLanguage *string,
	maxPlayerCount *int,
) (User, error) {
	if caller == nil {
		return User{}, NewBadRequestUserError(Tr("Caller cannot be null."))
	}

	callerIsAdmin := caller.IsAdmin

	if user.UUID != caller.UUID && !callerIsAdmin {
		return User{}, NewBadRequestUserError(Tr("You are not authorized to update that user."))
	}

	if password != nil {
		if err := app.ValidatePassword(*password); err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid password: %s", err))
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
			return User{}, NewBadRequestUserError(Tr("Cannot change admin status of user without having admin privileges yourself."))
		}
		if !(*isAdmin) && app.IsDefaultAdmin(&user) {
			return User{}, NewBadRequestUserError(Tr("Cannot revoke admin status of a default admin."))
		}
		user.IsAdmin = *isAdmin
	}

	if preferredLanguage != nil {
		if !IsValidPreferredLanguage(*preferredLanguage) {
			return User{}, NewBadRequestUserError(Tr("Invalid preferred language."))
		}
		user.PreferredLanguage = *preferredLanguage
	}

	if chatMode != nil {
		if !callerIsAdmin {
			return User{}, NewBadRequestUserError(Tr("Cannot change chat mode without admin privileges."))
		}
		if !IsValidChatMode(*chatMode) {
			return User{}, NewBadRequestUserError(Tr("Invalid chat mode."))
		}
		user.ChatMode = *chatMode
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
			return User{}, NewBadRequestUserError(Tr("Cannot set a max player count without admin privileges."))
		}
		err := app.ValidateMaxPlayerCount(*maxPlayerCount)
		if err != nil {
			return User{}, NewBadRequestUserError(Tr("Invalid max player count: %s", err))
		}
		user.MaxPlayerCount = *maxPlayerCount
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if isDisabled != nil {
			if !callerIsAdmin {
				return NewBadRequestUserError(Tr("Cannot change disabled status of user without having admin privileges yourself."))
			}
			err := app.SetIsDisabled(tx, &user, *isDisabled)
			if err != nil {
				return err
			}
		}

		if password != nil {
			// If password was changed, invalidate all clients
			if err := tx.Model(Client{}).
				Where("user_uuid = ?", user.UUID).
				Update("version", gorm.Expr("version + ?", 1)).
				Error; err != nil {
				return err
			}
		} else if resetMinecraftToken {
			// If only the Minecraft token was changed, invalidate only clients
			// who last authenticated by Minecraft token
			if err := tx.Model(Client{}).
				Where(
					"user_uuid = ? AND auth_method in (?, ?)",
					user.UUID,
					AuthMethodUnknown,
					AuthMethodMinecraftToken,
				).
				Update("version", gorm.Expr("version + ?", 1)).
				Error; err != nil {
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

func (app *App) SetIsDisabled(db *gorm.DB, user *User, isDisabled bool) error {
	user.IsDisabled = isDisabled
	if isDisabled {
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
		return NewUserErrorWithCode(http.StatusForbidden, Tr("You are not an admin."))
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
		return UserOIDCIdentity{}, NewBadRequestUserError(Tr("Caller cannot be null."))
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && !callerIsAdmin {
		return UserOIDCIdentity{}, NewBadRequestUserError(Tr("Can't link an OIDC account for another user unless you're an admin."))
	}

	var user User
	if err := app.DB.First(&user, "uuid = ?", userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return UserOIDCIdentity{}, NewBadRequestUserError(Tr("User not found."))
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
				return NewBadRequestUserError(Tr("That %s account is already linked to another user.", provider.Config.Name))
			}
			if IsErrorUniqueFailedField(err, "user_oidc_identities.issuer") {
				provider, ok := app.OIDCProvidersByIssuer[issuer]
				if !ok {
					return fmt.Errorf("Unknown OIDC provider: %s", issuer)
				}
				return NewBadRequestUserError(Tr("That user is already linked to a %s account.", provider.Config.Name))
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
		return NewBadRequestUserError(Tr("Caller cannot be null."))
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && !callerIsAdmin {
		return NewBadRequestUserError(Tr("Can't unlink an OIDC account for another user unless you're an admin."))
	}

	provider, ok := app.OIDCProvidersByName[providerName]
	if !ok {
		return NewBadRequestUserError(Tr("Unknown OIDC provider: %s", providerName))
	}

	return app.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Where("user_uuid = ? AND issuer = ?", userUUID, provider.Config.Issuer).Delete(&UserOIDCIdentity{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return NewUserErrorWithCode(http.StatusNotFound, Tr("No linked %s account found.", providerName))
		}

		var count int64
		if err := tx.Model(&UserOIDCIdentity{}).Where("user_uuid = ?", userUUID).Count(&count).Error; err != nil {
			return err
		}

		if count == 0 {
			return NewBadRequestUserError(Tr("Can't remove the last linked OIDC account."))
		}

		return nil
	})
}

func (app *App) PrimaryPlayerSkinURL(user *User) (*string, error) {
	if len(user.Players) == 0 {
		return nil, nil
	}

	player := (func() mo.Option[*Player] {
		if len(user.Players) == 0 {
			return mo.None[*Player]()
		}

		for _, player := range user.Players {
			if player.Name == user.Username {
				if player.SkinHash.Valid {
					return mo.Some(&player)
				}
				break
			}
		}

		playersDecreasingAge := make([]*Player, 0, len(user.Players))
		for i := range user.Players {
			playersDecreasingAge = append(playersDecreasingAge, &user.Players[i])
		}
		slices.SortFunc(playersDecreasingAge, func(a *Player, b *Player) int {
			return a.CreatedAt.Compare(b.CreatedAt)
		})

		for _, player := range playersDecreasingAge {
			if player.SkinHash.Valid {
				return mo.Some(player)
			}
		}

		return mo.None[*Player]()
	})()

	if p, ok := player.Get(); ok {
		skinURL, err := app.SkinURL(p.SkinHash.String)
		if err != nil {
			return nil, err
		}
		return &skinURL, nil
	}

	return nil, nil
}
