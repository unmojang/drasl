package main

import (
	"bytes"
	"image/png"

	"github.com/HugoSmits86/nativewebp"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupRenderTest(t *testing.T) (*TestSuite, *Player, *http.Cookie) {
	ts := &TestSuite{}
	config := testConfig()
	// Use the embedded default skin (no Mojang download) for skinless players.
	config.EnableVanillaDefaultSkins = false
	ts.Setup(config)

	_, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, "renderUser")
	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", "renderUser").Error)
	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "user_uuid = ?", user.UUID).Error)
	return ts, &player, browserTokenCookie
}

func TestRenderPlayer(t *testing.T) {
	t.Parallel()
	ts, player, browserTokenCookie := setupRenderTest(t)
	defer ts.Teardown()

	assert.Nil(t, ts.App.SetSkinAndSave(player, bytes.NewReader(RED_SKIN)))
	assert.Nil(t, ts.App.SetCapeAndSave(player, bytes.NewReader(RED_CAPE)))
	skinHash := *UnmakeNullString(&player.SkinHash)
	capeHash := *UnmakeNullString(&player.CapeHash)
	authed := []http.Cookie{*browserTokenCookie}
	base := "/web/render/player/" + player.UUID

	t.Run("front returns a WebP", func(t *testing.T) {
		rec := ts.Get(t, ts.Server, base, authed, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "image/webp", rec.Header().Get("Content-Type"))
		img, err := nativewebp.Decode(rec.Body)
		assert.Nil(t, err)
		assert.Greater(t, img.Bounds().Dx(), 0)
		assert.NotEqual(t, "", rec.Header().Get("ETag"))
	})

	t.Run("back returns a WebP", func(t *testing.T) {
		rec := ts.Get(t, ts.Server, base+"/back", authed, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		_, err := nativewebp.Decode(rec.Body)
		assert.Nil(t, err)
	})

	t.Run("render is cached on disk", func(t *testing.T) {
		_, err := os.Stat(ts.App.GetPlayerRenderPath(skinHash, capeHash, "front"))
		assert.Nil(t, err)
	})

	t.Run("unauthenticated request is rejected", func(t *testing.T) {
		rec := ts.Get(t, ts.Server, base, nil, nil)
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})

	t.Run("If-None-Match returns 304", func(t *testing.T) {
		rec := ts.Get(t, ts.Server, base, authed, nil)
		etag := rec.Header().Get("ETag")
		assert.NotEqual(t, "", etag)
		req := httptest.NewRequest(http.MethodGet, base, nil)
		req.AddCookie(browserTokenCookie)
		req.Header.Set("If-None-Match", etag)
		rec2 := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec2, req)
		assert.Equal(t, http.StatusNotModified, rec2.Code)
	})

	t.Run("unknown player returns 404", func(t *testing.T) {
		rec := ts.Get(t, ts.Server, "/web/render/player/00000000-0000-0000-0000-000000000000", authed, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("replacing the skin removes cached renders", func(t *testing.T) {
		_, err := ts.App.RenderPlayer(player, false)
		assert.Nil(t, err)
		frontPath := ts.App.GetPlayerRenderPath(skinHash, capeHash, "front")
		_, err = os.Stat(frontPath)
		assert.Nil(t, err)

		assert.Nil(t, ts.App.SetSkinAndSave(player, nil))
		_, err = os.Stat(frontPath)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestFrontVanillaSkin(t *testing.T) {
	t.Parallel()
	ts, _, browserTokenCookie := setupRenderTest(t)
	defer ts.Teardown()

	skin := vanillaSkin{name: "efe", slim: true}
	assert.Nil(t, os.MkdirAll(path.Dir(ts.App.vanillaDefaultSkinPath(skin)), os.ModePerm))
	assert.Nil(t, os.WriteFile(ts.App.vanillaDefaultSkinPath(skin), RED_SKIN, 0666))

	authed := []http.Cookie{*browserTokenCookie}

	rec := ts.Get(t, ts.Server, "/web/render/vanilla-skin/slim/efe.png", authed, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/png", rec.Header().Get("Content-Type"))
	_, err := png.Decode(rec.Body)
	assert.Nil(t, err)

	for _, p := range []string{"/web/render/vanilla-skin/slim/nobody.png", "/web/render/vanilla-skin/tall/efe.png"} {
		rec := ts.Get(t, ts.Server, p, authed, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, p)
	}
}

func TestRenderPlayerNoSkin(t *testing.T) {
	t.Parallel()
	ts, player, browserTokenCookie := setupRenderTest(t) // vanilla defaults disabled
	defer ts.Teardown()

	// No player skin, no operator default, vanilla disabled: nothing to render.
	assert.False(t, player.SkinHash.Valid)
	assert.False(t, ts.App.PlayerHasSkin(player))

	authed := []http.Cookie{*browserTokenCookie}
	for _, suffix := range []string{"", "/back"} {
		rec := ts.Get(t, ts.Server, "/web/render/player/"+player.UUID+suffix, authed, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, suffix)
	}

	for _, urlFn := range []func(*Player) (*string, error){
		ts.App.PlayerBodyRenderURL, ts.App.PlayerBodyBackRenderURL, ts.App.PlayerViewerSkinURL,
	} {
		u, err := urlFn(player)
		assert.Nil(t, err)
		assert.Nil(t, u)
	}
}
