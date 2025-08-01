package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/samber/mo"
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
			return nil, nil, NewBadRequestUserError("Setting a %s texture is not allowed.", textureType)
		}
		if textureReader != nil && textureURL != nil {
			return nil, nil, NewBadRequestUserError("Can't specify both a file and a URL for %s texture.", textureType)
		}
		if textureURL != nil {
			if !app.Config.AllowTextureFromURL && !callerIsAdmin {
				return nil, nil, NewBadRequestUserError("Setting a %s from a URL is not allowed.", textureType)
			}
			res, err := MakeHTTPClient().Get(*textureURL)
			if err != nil {
				return nil, nil, NewBadRequestUserError("Couldn't download a %s from that URL: %s", textureType, err)
			}
			defer res.Body.Close()
			bodyReader := res.Body.(io.Reader)
			textureReader = &bodyReader
		}
		validTextureHandle, err := app.GetTextureReader(textureType, *textureReader)
		if err != nil {
			return nil, nil, NewBadRequestUserError("Error using that %s: %s", textureType, err)
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
	existingPlayer bool,
	challengeToken *string,
	fallbackPlayer *string,
	skinModel *string,
	skinReader *io.Reader,
	skinURL *string,
	capeReader *io.Reader,
	capeURL *string,
) (Player, error) {
	if caller == nil {
		return Player{}, NewBadRequestUserError("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if userUUID != caller.UUID && !callerIsAdmin {
		return Player{}, NewBadRequestUserError("Can't create a player belonging to another user unless you're an admin.")
	}

	tx := app.DB.Session(&gorm.Session{FullSaveAssociations: true}).Begin()
	defer tx.Rollback()

	var user User
	if err := tx.First(&user, "uuid = ?", userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Player{}, NewBadRequestUserError("User not found.")
		}
		return Player{}, err
	}

	if !app.Config.AllowAddingDeletingPlayers && !callerIsAdmin {
		return Player{}, NewBadRequestUserError("You are not allowed to create new players.")
	}

	maxPlayerCount := app.GetMaxPlayerCount(&user)
	if maxPlayerCount != Constants.MaxPlayerCountUnlimited && len(user.Players) >= maxPlayerCount && !callerIsAdmin {
		return Player{}, &UserError{
			Code:    mo.Some(http.StatusBadRequest),
			Message: "You are only allowed to own %d player.",
			Plural: mo.Some(Plural{
				Message: "You are only allowed to own %d players", N: maxPlayerCount,
			}),
			Params: []any{maxPlayerCount},
		}
	}

	if err := app.ValidatePlayerName(playerName); err != nil {
		return Player{}, NewBadRequestUserError("Invalid player name: %s", err)
	}

	var playerUUID string
	if existingPlayer {
		// Import player
		if !app.Config.RegistrationExistingPlayer.Allow && !callerIsAdmin {
			return Player{}, NewBadRequestUserError("Importing an existing player is not allowed.")
		}

		if chosenUUID != nil {
			return Player{}, NewBadRequestUserError("Can't simultaneously import an existing player and choose a UUID.")
		}

		var err error
		details, err := app.ValidateChallenge(playerName, challengeToken)
		if err != nil {
			if app.Config.ImportExistingPlayer.RequireSkinVerification {
				return Player{}, NewBadRequestUserError("Couldn't verify your skin, maybe try again: %s", err)
			} else {
				return Player{}, NewBadRequestUserError("Couldn't find your account, maybe try again: %s", err)
			}
		}
		playerName = details.Username

		if err := app.ValidatePlayerName(playerName); err != nil {
			return Player{}, NewBadRequestUserError("Invalid player name: %s", err)
		}
		playerUUID = details.UUID
	} else {
		// New player registration
		if !app.Config.RegistrationNewPlayer.Allow && !callerIsAdmin {
			return Player{}, NewBadRequestUserError("Creating a new player is not allowed.")
		}

		if chosenUUID == nil {
			var err error
			playerUUID, err = app.NewPlayerUUID(playerName)
			if err != nil {
				return Player{}, err
			}
		} else {
			if !app.Config.CreateNewPlayer.AllowChoosingUUID && !callerIsAdmin {
				return Player{}, NewBadRequestUserError("Choosing a UUID is not allowed.")
			}
			chosenUUIDStruct, err := uuid.Parse(*chosenUUID)
			if err != nil {
				return Player{}, NewBadRequestUserError("Invalid UUID: %s", err)
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
		return Player{}, NewBadRequestUserError("Invalid fallback player: %s", err)
	}

	if skinModel == nil {
		skinModel = Ptr(SkinModelClassic)
	}
	if !IsValidSkinModel(*skinModel) {
		return Player{}, NewBadRequestUserError("Invalid skin model.")
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
			return Player{}, NewBadRequestUserError("That player name is taken.")
		} else if IsErrorUniqueFailedField(err, "players.uuid") {
			return Player{}, NewBadRequestUserError("That UUID is taken.")
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return Player{}, NewBadRequestUserError("That player name is in use as another user's username.")
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
			return player, NewBadRequestUserError("Error saving the skin.")
		}
	}

	if capeHash != nil {
		err = app.WriteCape(*capeHash, capeBuf)
		if err != nil {
			return player, NewBadRequestUserError("Error saving the cape.")
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
		return Player{}, NewBadRequestUserError("Caller cannot be null.")
	}

	callerIsAdmin := caller.IsAdmin

	if player.UserUUID != caller.UUID && !callerIsAdmin {
		return Player{}, NewBadRequestUserError("Can't update a player belonging to another user unless you're an admin.")
	}

	if playerName != nil && *playerName != player.Name {
		if !app.Config.AllowChangingPlayerName && !callerIsAdmin {
			return Player{}, NewBadRequestUserError("Changing your player name is not allowed.")
		}
		if err := app.ValidatePlayerName(*playerName); err != nil {
			return Player{}, NewBadRequestUserError("Invalid player name: %s", err)
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
			return Player{}, NewBadRequestUserError("Invalid fallback player: %s", err)
		}
		player.FallbackPlayer = *fallbackPlayer
	}

	if skinModel != nil {
		if !IsValidSkinModel(*skinModel) {
			return Player{}, NewBadRequestUserError("Invalid skin model.")
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
			return Player{}, NewBadRequestUserError("That player name is taken.")
		} else if IsErrorPlayerNameTakenByUsername(err) {
			return Player{}, NewBadRequestUserError("That player name is in use as another user's username.")
		}
		return Player{}, err
	}

	if !PtrEquals(oldSkinHash, newSkinHash) {
		if newSkinHash != nil {
			err = app.WriteSkin(*newSkinHash, skinBuf)
			if err != nil {
				return Player{}, NewBadRequestUserError("Error saving the skin.")
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
				return Player{}, NewBadRequestUserError("Error saving the cape.")
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

func (app *App) ValidateChallenge(playerName string, challengeToken *string) (*ProxiedAccountDetails, error) {
	base, err := url.Parse(app.Config.ImportExistingPlayer.AccountURL)
	if err != nil {
		return nil, err
	}
	base.Path, err = url.JoinPath(base.Path, "users/profiles/minecraft/"+playerName)
	if err != nil {
		return nil, err
	}

	res, err := MakeHTTPClient().Get(base.String())
	if err != nil {
		log.Printf("Couldn't access the registration server at %s: %s\n", base.String(), err)
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		log.Printf("Request to registration server at %s resulted in status code %d\n", base.String(), res.StatusCode)
		return nil, NewUserError("registration server returned an error")
	}

	var idRes PlayerNameToIDResponse
	err = json.NewDecoder(res.Body).Decode(&idRes)
	if err != nil {
		return nil, err
	}

	base, err = url.Parse(app.Config.ImportExistingPlayer.SessionURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SessionURL %s: %s", app.Config.ImportExistingPlayer.SessionURL, err)
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
		return nil, NewUserError("registration server returned an error")
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
	if !app.Config.ImportExistingPlayer.RequireSkinVerification {
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
				return nil, NewUserError("player does not have a skin")
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
				return nil, NewUserError("invalid image")
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
				return nil, NewUserError("missing challenge token")
			}
			correctChallenge := app.GetChallenge(playerName, *challengeToken)

			if !bytes.Equal(challenge, correctChallenge) {
				return nil, NewUserError("skin does not match")
			}

			return &details, nil
		}
	}

	return nil, NewUserError("registration server didn't return textures")
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
		return nil, NewBadRequestUserError("Invalid player name: %s", err)
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
	if !app.Config.AllowAddingDeletingPlayers && !caller.IsAdmin {
		return NewUserErrorWithCode(http.StatusForbidden, "You are not allowed to delete players.")
	}

	if caller.UUID != player.UserUUID && !caller.IsAdmin {
		return NewUserErrorWithCode(http.StatusForbidden, "You don't own that player.")
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
		result = app.DB.Preload("User").First(&player, "offline_uuid = ?", uuid_)
		if result.Error == nil {
			return &player, &player.User, nil
		}
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil, result.Error
		}
	}

	return nil, nil, nil
}
