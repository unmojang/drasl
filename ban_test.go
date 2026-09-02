package main

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBanPolicy(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}
	ts.Setup(testConfig())
	defer ts.Teardown()

	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)
	player := user.Players[0]

	t.Run("normalizes and resolves multiplayer bans", func(t *testing.T) {
		reasonID := 29
		ban, err := ts.App.CreateBan(BanTypeUser, strings.ReplaceAll(user.UUID, "-", ""), &reasonID, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, user.UUID, ban.Target)
		assert.NotEqual(t, "", ban.ID)

		active, err := ts.App.ActiveMultiplayerBan(user.UUID, player.UUID)
		assert.Nil(t, err)
		assert.NotNil(t, active)
		assert.Equal(t, ban.ID, active.ID)

		assert.Nil(t, ts.App.DB.Delete(&ban).Error)
	})

	t.Run("generates custom reason IDs", func(t *testing.T) {
		message := "Repeated local rule evasion"
		ban, err := ts.App.CreateBan(BanTypePlayer, player.UUID, nil, &message, nil)
		assert.Nil(t, err)
		assert.GreaterOrEqual(t, int(ban.ReasonID.Int64), MinCustomBanReasonID)
		assert.Equal(t, message, ban.ReasonMessage.String)
		assert.Nil(t, ts.App.DB.Delete(&ban).Error)

		customID := MinCustomBanReasonID
		_, err = ts.App.CreateBan(BanTypePlayer, player.UUID, &customID, nil, nil)
		assert.Error(t, err)
	})

	t.Run("rejects administrator identity bans", func(t *testing.T) {
		admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, "banAdmin")
		admin.IsAdmin = true
		assert.Nil(t, ts.App.DB.Save(admin).Error)

		reasonID := 29
		_, err := ts.App.CreateBan(BanTypeUser, admin.UUID, &reasonID, nil, nil)
		assert.EqualError(t, err, "Administrators cannot be banned.")
		_, err = ts.App.CreateBan(BanTypePlayer, admin.Players[0].UUID, &reasonID, nil, nil)
		assert.EqualError(t, err, "Administrators cannot be banned.")
	})

	t.Run("deletes bans when an update expires them", func(t *testing.T) {
		reasonID := 21
		ban, err := ts.App.CreateBan(BanTypePlayer, player.UUID, &reasonID, nil, nil)
		assert.Nil(t, err)

		past := sql.NullTime{Time: time.Now().Add(-time.Minute), Valid: true}
		_, err = ts.App.UpdateBan(&ban, nil, nil, &past)
		assert.Nil(t, err)

		active, err := ts.App.ActiveBan(BanTypePlayer, player.UUID)
		assert.Nil(t, err)
		assert.Nil(t, active)
	})

	t.Run("emits name actions and rejects the banned name", func(t *testing.T) {
		ban, err := ts.App.CreateBan(BanTypeName, player.Name, nil, nil, nil)
		assert.Nil(t, err)

		var updated Player
		assert.Nil(t, ts.App.DB.First(&updated, "uuid = ?", player.UUID).Error)
		actions, err := ts.App.ProfileActions(&updated)
		assert.Nil(t, err)
		assert.Equal(t, []SessionProfileAction{NewSessionProfileAction(ProfileActionForcedNameChange)}, actions)
		assert.Error(t, ts.App.EnsureNameAllowed(strings.ToUpper(player.Name)))

		assert.Nil(t, ts.App.DB.Delete(&ban).Error)
	})

	t.Run("removes and rejects banned textures", func(t *testing.T) {
		assert.Nil(t, ts.App.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN)))
		assert.Nil(t, ts.App.SetCapeAndSave(&player, bytes.NewReader(RED_CAPE)))

		skinBan, err := ts.App.CreateBan(BanTypeSkin, RED_SKIN_HASH, nil, nil, nil)
		assert.Nil(t, err)
		bannedAsCape, err := ts.App.IsTextureBanned(BanTypeCape, RED_SKIN_HASH)
		assert.Nil(t, err)
		assert.False(t, bannedAsCape)
		capeBan, err := ts.App.CreateBan(BanTypeCape, RED_CAPE_HASH, nil, nil, nil)
		assert.Nil(t, err)
		bannedAsSkin, err := ts.App.IsTextureBanned(BanTypeSkin, RED_CAPE_HASH)
		assert.Nil(t, err)
		assert.False(t, bannedAsSkin)

		var updated Player
		assert.Nil(t, ts.App.DB.First(&updated, "uuid = ?", player.UUID).Error)
		assert.False(t, updated.SkinHash.Valid)
		assert.False(t, updated.CapeHash.Valid)
		assert.Equal(t, skinBan.ID, updated.UsingBannedSkinBanID.String)
		assert.Error(t, ts.App.SetSkinAndSave(&updated, bytes.NewReader(RED_SKIN)))
		assert.Error(t, ts.App.SetCapeAndSave(&updated, bytes.NewReader(RED_CAPE)))

		assert.Nil(t, ts.App.DB.Delete(&skinBan).Error)
		assert.Nil(t, ts.App.DB.Delete(&capeBan).Error)
		var afterUnban Player
		assert.Nil(t, ts.App.DB.First(&afterUnban, "uuid = ?", player.UUID).Error)
		assert.False(t, afterUnban.UsingBannedSkinBanID.Valid)
	})

	t.Run("resolves profile actions independently", func(t *testing.T) {
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Nil(t, ts.App.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN)))

		nameBan, err := ts.App.CreateBan(BanTypeName, player.Name, nil, nil, nil)
		assert.Nil(t, err)
		skinBan, err := ts.App.CreateBan(BanTypeSkin, RED_SKIN_HASH, nil, nil, nil)
		assert.Nil(t, err)

		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		actions, err := ts.App.ProfileActions(&player)
		assert.Nil(t, err)
		assert.Equal(t, []SessionProfileAction{
			NewSessionProfileAction(ProfileActionForcedNameChange),
			NewSessionProfileAction(ProfileActionUsingBannedSkin),
		}, actions)

		newName := "ResolvedName"
		player, err = ts.App.UpdatePlayer(user, player, &newName, nil, nil, nil, nil, false, nil, nil, false)
		assert.Nil(t, err)
		actions, err = ts.App.ProfileActions(&player)
		assert.Nil(t, err)
		assert.Equal(t, []SessionProfileAction{NewSessionProfileAction(ProfileActionUsingBannedSkin)}, actions)

		assert.Nil(t, ts.App.SetSkinAndSave(&player, nil))
		actions, err = ts.App.ProfileActions(&player)
		assert.Nil(t, err)
		assert.Empty(t, actions)

		assert.Nil(t, ts.App.DB.Delete(&nameBan).Error)
		assert.Nil(t, ts.App.DB.Delete(&skinBan).Error)
	})
}
