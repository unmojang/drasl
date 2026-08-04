package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestPlayerPreview(t *testing.T) {
	t.Parallel()
	{
		ts := &TestSuite{}

		config := testConfig()
		// Keep the Mojang download out of tests.
		config.EnableVanillaDefaultSkins = false
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Serve a vanilla default skin texture", ts.testFrontVanillaSkin)
		t.Run("Preview a player with no skin", ts.testPreviewPlayerNoSkin)
		t.Run("The preview follows the player's arm model", ts.testPreviewFollowsArmModel)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		config.EnableVanillaDefaultSkins = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("A player's avatar follows their preview", ts.testPlayerAvatarSkinURLFollowsPreview)
		t.Run("A player with a cape but no skin wears the vanilla default", ts.testVanillaDefaultSkinWithCape)
	}
	{
		ts := &TestSuite{}
		ts.SetupAux(testConfig())

		config := testConfig()
		config.EnableVanillaDefaultSkins = false
		config.FallbackAPIServers = []FallbackAPIServerConfig{ts.ToFallbackAPIServerAuthlibInjector(ts.AuxApp, "Aux")}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Preview a player's fallback textures", ts.testPlayerFallbackTextures)
		t.Run("Fallback textures are named consistently", ts.testResolvePlayerTexturesConsistency)
	}
}

func (ts *TestSuite) createPreviewTestPlayer(t *testing.T, username string) (*Player, *http.Cookie) {
	_, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", username).Error)
	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "user_uuid = ?", user.UUID).Error)
	return &player, browserTokenCookie
}

func (ts *TestSuite) testPlayerFallbackTextures(t *testing.T) {
	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)
	var auxUser User
	assert.Nil(t, ts.AuxApp.DB.First(&auxUser, "username = ?", TEST_USERNAME).Error)
	auxPlayer := auxUser.Players[0]
	assert.Nil(t, ts.AuxApp.SetSkinAndSave(&auxPlayer, bytes.NewReader(RED_SKIN)))
	assert.Nil(t, ts.AuxApp.SetCapeAndSave(&auxPlayer, bytes.NewReader(RED_CAPE)))

	ts.CreateTestUser(t, ts.App, ts.Server, "fallbackUser")
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", "fallbackUser").Error)
	player := &user.Players[0]
	player.FallbackPlayer = auxPlayer.UUID
	assert.Nil(t, ts.App.DB.Save(player).Error)

	t.Run("the fallback skin and cape are previewed", func(t *testing.T) {
		preview, err := ts.App.GetPlayerPreview(player)
		assert.Nil(t, err)
		assert.NotNil(t, preview.SkinURL)
		assert.NotNil(t, preview.CapeURL)

		// The previews point at the fallback server itself, as the game does.
		for _, textureURL := range []*string{preview.SkinURL, preview.CapeURL} {
			assert.Contains(t, *textureURL, ts.AuxApp.FrontEndURL)
		}
	})

	t.Run("the player's own skin wins over the fallback", func(t *testing.T) {
		assert.Nil(t, ts.App.SetSkinAndSave(player, bytes.NewReader(BLUE_SKIN)))
		defer func() { assert.Nil(t, ts.App.SetSkinAndSave(player, nil)) }()

		preview, err := ts.App.GetPlayerPreview(player)
		assert.Nil(t, err)
		skinURL, err := ts.App.SkinURL(*UnmakeNullString(&player.SkinHash))
		assert.Nil(t, err)
		assert.Equal(t, skinURL, *preview.SkinURL)
		// Any texture of their own leaves the forwarding path, cape included.
		assert.Nil(t, preview.CapeURL)
	})
}

func (ts *TestSuite) testFrontVanillaSkin(t *testing.T) {
	_, browserTokenCookie := ts.createPreviewTestPlayer(t, "vanillaSkinUser")

	skin := vanillaSkin{name: "efe", slim: true}
	assert.Nil(t, os.MkdirAll(path.Dir(ts.App.vanillaDefaultSkinPath(skin)), os.ModePerm))
	assert.Nil(t, os.WriteFile(ts.App.vanillaDefaultSkinPath(skin), RED_SKIN, 0666))

	authed := []http.Cookie{*browserTokenCookie}

	rec := ts.Get(t, ts.Server, "/web/vanilla-skin/slim/efe.png", authed, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/png", rec.Header().Get("Content-Type"))
	_, err := png.Decode(rec.Body)
	assert.Nil(t, err)

	for _, p := range []string{"/web/vanilla-skin/slim/nobody.png", "/web/vanilla-skin/tall/efe.png"} {
		rec := ts.Get(t, ts.Server, p, authed, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, p)
	}

	rec = ts.Get(t, ts.Server, "/web/vanilla-skin/slim/efe.png", nil, nil)
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testPreviewPlayerNoSkin(t *testing.T) {
	player, _ := ts.createPreviewTestPlayer(t, "noSkinUser")

	// No player skin, no operator default, vanilla disabled: nothing to show.
	assert.False(t, player.SkinHash.Valid)
	preview, err := ts.App.GetPlayerPreview(player)
	assert.Nil(t, err)
	assert.Nil(t, preview.SkinURL)
	assert.Nil(t, preview.CapeURL)
}

// The three consumers must name the same fallback texture.
func (ts *TestSuite) testResolvePlayerTexturesConsistency(t *testing.T) {
	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_OTHER_USERNAME)
	var auxUser User
	assert.Nil(t, ts.AuxApp.DB.First(&auxUser, "username = ?", TEST_OTHER_USERNAME).Error)
	auxPlayer := auxUser.Players[0]
	assert.Nil(t, ts.AuxApp.SetSkinAndSave(&auxPlayer, bytes.NewReader(RED_SKIN)))

	ts.CreateTestUser(t, ts.App, ts.Server, "consistencyUser")
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", "consistencyUser").Error)
	player := &user.Players[0]
	player.FallbackPlayer = auxPlayer.UUID
	assert.Nil(t, ts.App.DB.Save(player).Error)

	resolved, err := ts.App.ResolvePlayerTextures(player)
	assert.Nil(t, err)
	assert.Equal(t, TextureSourceFallback, resolved.Skin.Source)

	// Not the raw value: the upstream server stamps a fresh timestamp into it.
	property, err := ts.App.GetSkinTexturesProperty(player, false)
	assert.Nil(t, err)
	blob, err := base64.StdEncoding.DecodeString(property.Value)
	assert.Nil(t, err)
	var relayed texturesValue
	assert.Nil(t, json.Unmarshal(blob, &relayed))
	assert.NotNil(t, relayed.Textures.Skin)
	assert.Equal(t, resolved.Skin.URL, relayed.Textures.Skin.URL)

	profile, err := getServicesProfile(ts.App, player)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(profile.Skins))
	assert.Equal(t, resolved.Skin.URL, profile.Skins[0].URL)

	preview, err := ts.App.GetPlayerPreview(player)
	assert.Nil(t, err)
	assert.Equal(t, resolved.Skin.URL, *preview.SkinURL)
}

// A player with a cape but no skin wears the vanilla default for their UUID.
func (ts *TestSuite) testVanillaDefaultSkinWithCape(t *testing.T) {
	ts.CreateTestUser(t, ts.App, ts.Server, "vanillaUser")
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", "vanillaUser").Error)
	player := &user.Players[0]
	assert.Nil(t, ts.App.SetCapeAndSave(player, bytes.NewReader(RED_CAPE)))

	expected := vanillaDefaultSkins[vanillaDefaultSkinIndex(Unwrap(uuid.Parse(player.UUID)))]
	vanillaPath := ts.App.vanillaDefaultSkinPath(expected)
	assert.Nil(t, os.MkdirAll(path.Dir(vanillaPath), os.ModePerm))
	assert.Nil(t, os.WriteFile(vanillaPath, RED_SKIN, 0666))
	// Another player in the suite may hash to this same vanilla skin.
	defer func() { assert.Nil(t, os.Remove(vanillaPath)) }()

	preview, err := ts.App.GetPlayerPreview(player)
	assert.Nil(t, err)
	assert.NotNil(t, preview.CapeURL)
	assert.NotNil(t, preview.SkinURL)
	assert.Contains(t, *preview.SkinURL, "/web/vanilla-skin/"+vanillaSkinModelDir(expected.slim)+"/"+expected.name+".png")
	if expected.slim {
		assert.Equal(t, SkinModelSlim, preview.Model)
	} else {
		assert.Equal(t, SkinModelClassic, preview.Model)
	}
}

// The arm model is on the player, not in the texture.
func (ts *TestSuite) testPreviewFollowsArmModel(t *testing.T) {
	ts.CreateTestUser(t, ts.App, ts.Server, "classicUser")
	ts.CreateTestUser(t, ts.App, ts.Server, "slimUser")
	var classic, slim Player
	assert.Nil(t, ts.App.DB.First(&classic, "name = ?", "classicUser").Error)
	assert.Nil(t, ts.App.DB.First(&slim, "name = ?", "slimUser").Error)

	assert.Nil(t, ts.App.SetSkinAndSave(&classic, bytes.NewReader(RED_SKIN)))
	assert.Nil(t, ts.App.SetSkinAndSave(&slim, bytes.NewReader(RED_SKIN)))
	slim.SkinModel = SkinModelSlim
	assert.Nil(t, ts.App.DB.Save(&slim).Error)

	classicPreview, err := ts.App.GetPlayerPreview(&classic)
	assert.Nil(t, err)
	slimPreview, err := ts.App.GetPlayerPreview(&slim)
	assert.Nil(t, err)

	assert.Equal(t, *classicPreview.SkinURL, *slimPreview.SkinURL) // same texture
	assert.Equal(t, SkinModelClassic, classicPreview.Model)
	assert.Equal(t, SkinModelSlim, slimPreview.Model)
}

// The list avatar crops a head out of the texture the preview shows.
func (ts *TestSuite) testPlayerAvatarSkinURLFollowsPreview(t *testing.T) {
	ts.CreateTestUser(t, ts.App, ts.Server, "avatarUser")
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", "avatarUser").Error)
	player := &user.Players[0]
	assert.False(t, player.SkinHash.Valid)

	// No skin of their own and no vanilla skin on disk yet: nothing to show.
	avatar, err := ts.App.PlayerAvatarSkinURL(player)
	assert.Nil(t, err)
	assert.Nil(t, avatar)

	vs := vanillaDefaultSkins[vanillaDefaultSkinIndex(Unwrap(uuid.Parse(player.UUID)))]
	vanillaPath := ts.App.vanillaDefaultSkinPath(vs)
	assert.Nil(t, os.MkdirAll(path.Dir(vanillaPath), os.ModePerm))
	assert.Nil(t, os.WriteFile(vanillaPath, RED_SKIN, 0666))

	// Now the preview shows the vanilla default, so the avatar must too.
	preview, err := ts.App.GetPlayerPreview(player)
	assert.Nil(t, err)
	assert.NotNil(t, preview.SkinURL)
	avatar, err = ts.App.PlayerAvatarSkinURL(player)
	assert.Nil(t, err)
	assert.NotNil(t, avatar)
	assert.Equal(t, *preview.SkinURL, *avatar)

	// And the user list picks the same one up.
	assert.Nil(t, ts.App.DB.Preload("Players").First(&user, "username = ?", "avatarUser").Error)
	primary, err := ts.App.PrimaryPlayerSkinURL(&user)
	assert.Nil(t, err)
	assert.NotNil(t, primary)
	assert.Equal(t, *avatar, *primary)
}
