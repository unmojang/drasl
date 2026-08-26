package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lukechampine.com/blake3"
)

func (app *App) getTexture(
	textureType string,
	caller *User,
	textureReader *io.Reader,
	textureURL *string,
) (textureHash *string, textureBuf *bytes.Buffer, err error) {
	callerIsAdmin := caller != nil && caller.IsAdmin

	if textureReader != nil || textureURL != nil {
		allowed := false
		switch textureType {
		case TextureTypeSkin:
			allowed = app.Config.AllowSkins
		case TextureTypeCape:
			allowed = app.Config.AllowCapes
		}
		if !allowed && !callerIsAdmin {
			return nil, nil, NewBadRequestUserError(Tr("Setting a %s texture is not allowed.", textureType))
		}
		if textureReader != nil && textureURL != nil {
			return nil, nil, NewBadRequestUserError(Tr("Can't specify both a file and a URL for %s texture.", textureType))
		}
		if textureURL != nil {
			if !app.Config.AllowTextureFromURL && !callerIsAdmin {
				return nil, nil, NewBadRequestUserError(Tr("Setting a %s from a URL is not allowed.", textureType))
			}
			res, err := MakeHTTPClient().Get(*textureURL)
			if err != nil {
				return nil, nil, NewBadRequestUserError(Tr("Couldn't download a %[1]s from that URL: %[2]s", textureType, err))
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			textureReader = &bodyReader
		}
		validTextureHandle, err := app.GetTextureReader(textureType, *textureReader)
		if err != nil {
			return nil, nil, NewBadRequestUserError(Tr("Error using that %[1]s: %[2]s", textureType, err))
		}
		var hash string
		textureBuf, hash, err = app.ReadTexture(validTextureHandle)
		if err != nil {
			return nil, nil, err
		}
		textureHash = &hash
	}

	return
}

func (app *App) CreatePlayer(
	caller *User,
	userUUID string,
	playerName string,
	chosenUUID *string,
	// If non-nil, import an existing player from the named fallback API server.
	// nil means create a new player.
	fallbackAPIServerNickname *string,
	challengeToken *string,
	fallbackPlayer *string,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	capeReader *io.Reader,
	capeURL *string,
) (Player, error) {
	if caller == nil {
		return Player{}, NewBadRequestUserError(Tr("Caller cannot be null."))
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && !callerIsAdmin {
		return Player{}, NewBadRequestUserError(Tr("Can't create a player belonging to another user unless you're an admin."))
	}

	tx := app.DB.Session(&gorm.Session{FullSaveAssociations: true}).Begin()
	defer tx.Rollback()

	var user User
	if err := tx.First(&user, "uuid = ?", userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Player{}, NewBadRequestUserError(Tr("User not found."))
		}
		return Player{}, err
	}

	maxPlayerCount := app.GetMaxPlayerCount(&user)
	if maxPlayerCount != Constants.MaxPlayerCountUnlimited && len(user.Players) >= maxPlayerCount && !callerIsAdmin {
		return Player{}, NewBadRequestUserError(TrN("You are only allowed to have %d player.", "You are only allowed to have %d players", maxPlayerCount, maxPlayerCount))
	}

	if err := app.ValidatePlayerName(playerName); err != nil {
		return Player{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
	}

	var playerUUID string
	if fallbackAPIServerNickname != nil {
		// Import player
		var importConfig *importExistingPlayerConfig
		for i := range app.Config.ImportExistingPlayer {
			if app.Config.ImportExistingPlayer[i].FallbackAPIServerNickname == *fallbackAPIServerNickname {
				importConfig = &app.Config.ImportExistingPlayer[i]
				break
			}
		}
		if importConfig == nil {
			return Player{}, NewBadRequestUserError(Tr("Importing an existing player from %s is not allowed.", *fallbackAPIServerNickname))
		}

		fallbackAPIServer := app.FallbackAPIServers[*fallbackAPIServerNickname]
		if fallbackAPIServer == nil {
			return Player{}, NewBadRequestUserError(Tr("Unknown fallback API server: %s", *fallbackAPIServerNickname))
		}

		if chosenUUID != nil {
			return Player{}, NewBadRequestUserError(Tr("Can't simultaneously import an existing player and choose a UUID."))
		}

		details, err := app.ValidateChallenge(fallbackAPIServer, playerName, challengeToken, importConfig.RequireSkinVerification && !callerIsAdmin)
		if err != nil {
			if importConfig.RequireSkinVerification {
				return Player{}, NewBadRequestUserError(Tr("Couldn't verify your skin, maybe try again: %s", err))
			} else {
				return Player{}, NewBadRequestUserError(Tr("Couldn't find your account, maybe try again: %s", err))
			}
		}
		playerName = details.Username

		if err := app.ValidatePlayerName(playerName); err != nil {
			return Player{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
		}
		playerUUID = details.UUID
	} else {
		// New player registration
		if !app.Config.CreateNewPlayer.Allow && !callerIsAdmin {
			return Player{}, NewBadRequestUserError(Tr("Creating a new player is not allowed."))
		}

		if chosenUUID == nil {
			var err error
			playerUUID, err = app.NewPlayerUUID(playerName)
			if err != nil {
				return Player{}, err
			}
		} else {
			if !app.Config.CreateNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return Player{}, NewBadRequestUserError(Tr("Choosing a UUID is not allowed."))
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
			if err != nil {
				return Player{}, NewBadRequestUserError(Tr("Invalid UUID: %s", err))
			}
			playerUUID = chosenUUIDStruct.String()
		}
	}

	offlineUUID, err := OfflineUUID(playerName)
	if err != nil {
		return Player{}, err
	}

	if fallbackPlayer == nil {
		fallbackPlayer = &playerUUID
	}
	if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
		return Player{}, NewBadRequestUserError(Tr("Invalid fallback player: %s", err))
	}

	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return Player{}, NewBadRequestUserError(Tr("Invalid skin model."))
	}

	skinHash, skinBuf, err := app.getTexture("skin", caller, skinReader, skinURL)
	if err != nil {
		return Player{}, err
	}

	capeHash, capeBuf, err := app.getTexture("cape", caller, capeReader, capeURL)
	if err != nil {
		return Player{}, err
	}

	player := Player{
		UUID:              playerUUID,
		UserUUID:          userUUID,
		Clients:           []Client{},
		Name:              playerName,
		OfflineUUID:       offlineUUID,
		FallbackPlayer:    *fallbackPlayer,
		SkinModel:         *skinModel,
		SkinHash:          MakeNullString(skinHash),
		CapeHash:          MakeNullString(capeHash),
		CreatedAt:         time.Now(),
		NameLastChangedAt: time.Now(),
	}
	if err := tx.Create(&player).Error; err != nil {
		if IsErrorUniqueFailedField(err, "players.name") {
			return Player{}, NewBadRequestUserError(Tr("That player name is taken."))
		} else if IsErrorUniqueFailedField(err, "players.uuid") {
			return Player{}, NewBadRequestUserError(Tr("That UUID is taken."))
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return Player{}, NewBadRequestUserError(Tr("That player name is in use as another user's username."))
		} else {
			return Player{}, err
		}
	}

	user.Players = append(user.Players, player)
	if err := tx.Save(&user).Error; err != nil {
		return Player{}, err
	}
	if err := tx.Commit().Error; err != nil {
		return Player{}, err
	}

	if skinHash != nil {
		err = app.WriteSkin(*skinHash, skinBuf)
		if err != nil {
			return player, NewBadRequestUserError(Tr("Error saving the skin."))
		}
	}

	if capeHash != nil {
		err = app.WriteCape(*capeHash, capeBuf)
		if err != nil {
			return player, NewBadRequestUserError(Tr("Error saving the cape."))
		}
	}

	return player, nil
}

func (app *App) UpdatePlayer(
	caller *User,
	player Player,
	playerName *string,
	fallbackPlayer *string,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	deleteSkin bool,
	capeReader *io.Reader,
	capeURL *string,
	deleteCape bool,
) (Player, error) {
	if caller == nil {
		return Player{}, NewBadRequestUserError(Tr("Caller cannot be null."))
	}

	callerIsAdmin := caller.IsAdmin

	if player.UserUUID != caller.UUID && !callerIsAdmin {
		return Player{}, NewBadRequestUserError(Tr("Can't update a player belonging to another user unless you're an admin."))
	}

	if playerName != nil && *playerName != player.Name {
		if !app.Config.AllowChangingPlayerName && !callerIsAdmin {
			return Player{}, NewBadRequestUserError(Tr("Changing your player name is not allowed."))
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return Player{}, NewBadRequestUserError(Tr("Invalid player name: %s", err))
		}
		offlineUUID, err := OfflineUUID(*playerName)
		if err != nil {
			return Player{}, err
		}
		player.Name = *playerName
		player.OfflineUUID = offlineUUID
		player.NameLastChangedAt = time.Now()
	}

	if fallbackPlayer != nil && *fallbackPlayer != player.FallbackPlayer {
		if err := app.ValidatePlayerNameOrUUID(*fallbackPlayer); err != nil {
			return Player{}, NewBadRequestUserError(Tr("Invalid fallback player: %s", err))
		}
		player.FallbackPlayer = *fallbackPlayer
	}

	if skinModel != nil {
		if !IsValidSkinModel(*skinModel) {
			return Player{}, NewBadRequestUserError(Tr("Invalid skin model."))
		}
		player.SkinModel = *skinModel
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

	skinHash, skinBuf, err := app.getTexture("skin", caller, skinReader, skinURL)
	if err != nil {
		return Player{}, err
	}
	oldSkinHash := UnmakeNullString(&player.SkinHash)
	if skinHash != nil {
		player.SkinHash = MakeNullString(skinHash)
	} else if deleteSkin {
		player.SkinHash = MakeNullString(nil)
	}

	capeHash, capeBuf, err := app.getTexture("cape", caller, capeReader, capeURL)
	if err != nil {
		return Player{}, err
	}
	oldCapeHash := UnmakeNullString(&player.CapeHash)
	if capeHash != nil {
		player.CapeHash = MakeNullString(capeHash)
	} else if deleteCape {
		player.CapeHash = MakeNullString(nil)
	}

	newSkinHash := UnmakeNullString(&player.SkinHash)
	newCapeHash := UnmakeNullString(&player.CapeHash)

	err = app.DB.Save(&player).Error
	if err != nil {
		if IsErrorUniqueFailedField(err, "players.name") {
			return Player{}, NewBadRequestUserError(Tr("That player name is taken."))
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return Player{}, NewBadRequestUserError(Tr("That player name is in use as another user's username."))
		}
		return Player{}, err
	}

	if !PtrEquals(oldSkinHash, newSkinHash) {
		if newSkinHash != nil {
			err = app.WriteSkin(*newSkinHash, skinBuf)
			if err != nil {
				return Player{}, NewBadRequestUserError(Tr("Error saving the skin."))
			}
		}

		err = app.DeleteSkinIfUnused(oldSkinHash)
		if err != nil {
			return Player{}, err
		}
	}
	if !PtrEquals(oldCapeHash, newCapeHash) {
		if newCapeHash != nil {
			err = app.WriteCape(*newCapeHash, capeBuf)
			if err != nil {
				return Player{}, NewBadRequestUserError(Tr("Error saving the cape."))
			}
		}

		err = app.DeleteCapeIfUnused(oldCapeHash)
		if err != nil {
			return Player{}, err
		}
	}

	return player, nil
}

type ProxiedAccountDetails struct {
	Username string
	UUID     string
}

// ImportExistingPlayerRegistrationServers returns the fallback API servers that
// allow registration from an existing player (via RegistrationUsernamePassword), in
// configured order.
func (app *App) ImportExistingPlayerRegistrationServers() []*FallbackAPIServer {
	out := make([]*FallbackAPIServer, 0, len(app.Config.RegistrationUsernamePassword.ImportExistingPlayer))
	for _, reg := range app.Config.RegistrationUsernamePassword.ImportExistingPlayer {
		if fb := app.FallbackAPIServers[reg.FallbackAPIServerNickname]; fb != nil {
			out = append(out, fb)
		}
	}
	return out
}

func (app *App) ValidateChallenge(fallbackAPIServer *FallbackAPIServer, playerName string, challengeToken *string, requireSkinVerification bool) (*ProxiedAccountDetails, error) {
	lowerName := strings.ToLower(playerName)
	responses := fallbackAPIServer.PlayerNamesToIDs(mapset.NewSet(lowerName))

	var idRes *PlayerNameToIDResponse
	for i := range responses {
		if strings.EqualFold(responses[i].Name, playerName) {
			idRes = &responses[i]
			break
		}
	}
	if idRes == nil {
		return nil, NewUserError(Tr("registration server returned an error"))
	}

	profileURL := fallbackAPIServer.SessionGetProfileByIDURL + "/" + url.PathEscape(idRes.ID)
	res, err := MakeHTTPClient().Get(profileURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Printf("Request to registration server at %s resulted in status code %d\n", profileURL, res.StatusCode)
		return nil, NewUserError(Tr("registration server returned an error"))
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

	details := ProxiedAccountDetails{
		Username: profileRes.Name,
		UUID:     accountUUID,
	}
	if !requireSkinVerification {
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
				return nil, NewUserError(Tr("player does not have a skin"))
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
				return nil, NewUserError(Tr("invalid image"))
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
				return nil, NewUserError(Tr("missing challenge token"))
			}
			correctChallenge := app.GetChallenge(playerName, *challengeToken)

			if !bytes.Equal(challenge, correctChallenge) {
				return nil, NewUserError(Tr("skin does not match"))
			}

			return &details, nil
		}
	}

	return nil, NewUserError(Tr("registration server didn't return textures"))
}

func MakeChallengeToken() (string, error) {
	return RandomBase62(16)
}

func (app *App) GetChallenge(playerName string, token string) []byte {
	// This challenge is nice because:
	// - it doesn't depend on any serverside state
	// - an attacker can't use it to verify a different player name, since the
	//   hash incorporates the player name
	// - an attacker can't generate their own challenges, since the hash
	//   includes a hash of the instance's private key
	// - an attacker can't steal the skin mid-verification and register the
	//   account themselves, since the hash incorporates a token known only to
	//   the verifying browser
	challengeBytes := bytes.Join([][]byte{
		[]byte(playerName),
		app.PrivateKeyB3Sum512[:],
		[]byte(token),
	}, []byte{byte(0)})

	sum := blake3.Sum512(challengeBytes)
	return sum[:]
}

func (app *App) GetChallengeSkin(playerName string, challengeToken string) ([]byte, error) {
	if err := app.ValidatePlayerName(playerName); err != nil {
		return nil, NewBadRequestUserError(Tr("Invalid player name: %s", err))
	}

	// challenge is a 512-bit, 64 byte checksum
	challenge := app.GetChallenge(playerName, challengeToken)

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

func (app *App) InvalidatePlayer(db *gorm.DB, player *Player) error {
	if player == nil {
		return nil
	}
	result := db.Model(Client{}).Where("player_uuid = ?", player.UUID).Update("version", gorm.Expr("version + ?", 1))
	return result.Error
}

func (app *App) InvalidateUser(db *gorm.DB, user *User) error {
	result := db.Model(Client{}).Where("user_uuid = ?", user.UUID).Update("version", gorm.Expr("version + ?", 1))
	return result.Error
}

func (app *App) DeletePlayer(caller *User, player *Player) error {
	if !app.Config.CreateNewPlayer.Allow && len(app.Config.ImportExistingPlayer) == 0 && !caller.IsAdmin {
		return NewUserErrorWithCode(http.StatusForbidden, Tr("You are not allowed to delete players."))
	}

	if caller.UUID != player.UserUUID && !caller.IsAdmin {
		return NewUserErrorWithCode(http.StatusForbidden, Tr("You don't own that player."))
	}

	if err := app.DB.Delete(player).Error; err != nil {
		return err
	}

	err := app.DeleteSkinIfUnused(UnmakeNullString(&player.SkinHash))
	if err != nil {
		return err
	}

	err = app.DeleteCapeIfUnused(UnmakeNullString(&player.CapeHash))
	if err != nil {
		return err
	}

	return nil
}

func (app *App) PlayerSkinURL(player *Player) (*string, error) {
	if !player.SkinHash.Valid {
		return nil, nil
	}
	url, err := app.SkinURL(player.SkinHash.String)
	if err != nil {
		return nil, err
	}
	return &url, nil
}

func (app *App) FindPlayerByUUIDOrOfflineUUID(uuid_ string) (*Player, *User, error) {
	var player Player
	result := app.DB.Preload("User").First(&player, "uuid = ?", uuid_)
	if result.Error == nil {
		return &player, &player.User, nil
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil, result.Error
	}

	if app.Config.OfflineSkins {
		var offlinePlayer Player
		result = app.DB.Preload("User").First(&offlinePlayer, "offline_uuid = ?", uuid_)
		if result.Error == nil {
			return &offlinePlayer, &offlinePlayer.User, nil
		}
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil, result.Error
		}
	}

	return nil, nil, nil
}
