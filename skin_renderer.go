package main

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/HugoSmits86/nativewebp"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	skin "github.com/unmojang/skin-render"
)

// Final size of a player render (supersampled internally), displayed smaller to
// leave headroom for hi-dpi displays.
const (
	playerRenderWidth  = 360
	playerRenderHeight = 540
	playerRenderPhi    = 21 // pitch
	playerRenderTime   = 90 // default frame (mid-stride)
	frontRenderTheta   = 30
	backRenderTheta    = 210
)

var renderIDSanitize = regexp.MustCompile(`[^0-9a-zA-Z.-]`)

func sanitizeRenderID(s string) string {
	return renderIDSanitize.ReplaceAllString(s, "-")
}

// renderSource is the resolved input for a player render: which skin and cape to
// draw and the cache identity of each. It is computed without loading or
// downloading anything, so it's cheap enough for ETag/cache-path use.
type renderSource struct {
	hasSkin  bool // false => no skin to render (no player skin, default, or vanilla)
	skinPath string
	slim     bool
	skinID   string
	capePath string // "" => no cape
	capeID   string
}

func (app *App) defaultSkinGlob() string {
	return path.Join(app.Config.StateDirectory, "default-skin", "*.png")
}
func (app *App) defaultCapeGlob() string {
	return path.Join(app.Config.StateDirectory, "default-cape", "*.png")
}

// resolveRenderSource picks the skin and cape for a player: their own texture,
// else an operator default, else (for skins) the vanilla Mojang default, else
// nothing (hasSkin false).
func (app *App) resolveRenderSource(player *Player) renderSource {
	var src renderSource

	switch {
	case player.SkinHash.Valid:
		src.hasSkin = true
		src.skinPath = app.GetSkinPath(player.SkinHash.String)
		src.slim = player.SkinModel == SkinModelSlim
		src.skinID = player.SkinHash.String
	default:
		if p, err := app.ChooseFileForUser(player, app.defaultSkinGlob()); err == nil && p != nil {
			src.hasSkin = true
			src.skinPath = *p
			src.slim = slimSkinRegex.MatchString(*p)
			src.skinID = "op-" + sanitizeRenderID(filepath.Base(*p))
		} else if app.Config.EnableVanillaDefaultSkins {
			if u, err := uuid.Parse(player.UUID); err == nil {
				vs := vanillaDefaultSkins[vanillaDefaultSkinIndex(u)]
				vanillaPath := app.vanillaDefaultSkinPath(vs)
				// Only use the vanilla default once it's downloaded
				if _, err := os.Stat(vanillaPath); err == nil {
					src.hasSkin = true
					src.skinPath = vanillaPath
					src.slim = vs.slim
					src.skinID = "va-" + vanillaSkinModelDir(vs.slim) + "-" + vs.name
				}
			}
		}
	}

	switch {
	case player.CapeHash.Valid:
		src.capePath = app.GetCapePath(player.CapeHash.String)
		src.capeID = player.CapeHash.String
	default:
		if p, err := app.ChooseFileForUser(player, app.defaultCapeGlob()); err == nil && p != nil {
			src.capePath = *p
			src.capeID = "op-" + sanitizeRenderID(filepath.Base(*p))
		} else {
			src.capeID = "none"
		}
	}
	return src
}

func (app *App) GetPlayerRenderPath(skinID, capeID, view string) string {
	dir := path.Join(app.Config.StateDirectory, "render", "player")
	return path.Join(dir, fmt.Sprintf("%s_%s_%s.webp", skinID, capeID, view))
}

func loadNRGBA(texturePath string) (*image.NRGBA, error) {
	b, err := os.ReadFile(texturePath)
	if err != nil {
		return nil, err
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if nrgba, ok := img.(*image.NRGBA); ok {
		return nrgba, nil
	}
	out := image.NewNRGBA(img.Bounds())
	draw.Draw(out, out.Bounds(), img, img.Bounds().Min, draw.Src)
	return out, nil
}

// loadRenderImages loads the skin and optional cape for a source, falling back to
// the embedded skin if the skin file can't be read.
func (app *App) loadRenderImages(src renderSource) (*image.NRGBA, *image.NRGBA) {
	skinImg, err := loadNRGBA(src.skinPath)
	if err != nil {
		skinImg = skin.GetDefaultSkin(src.slim)
	}

	var capeImg *image.NRGBA
	if src.capePath != "" {
		capeImg, _ = loadNRGBA(src.capePath)
	}
	return skinImg, capeImg
}

// RenderPlayer renders the player wearing their cape from the front (or the back
// "cape view"). Renders are cached on disk keyed by the skin and
// cape identities; DeletePlayerRenders* removes them when a texture is replaced.
func (app *App) RenderPlayer(player *Player, back bool) ([]byte, error) {
	src := app.resolveRenderSource(player)
	view, theta := "front", float64(frontRenderTheta)
	if back {
		view, theta = "back", backRenderTheta
	}
	renderPath := app.GetPlayerRenderPath(src.skinID, src.capeID, view)
	return app.cachedRender(renderPath, func() ([]byte, error) {
		skinImg, capeImg := app.loadRenderImages(src)
		rendered := skin.Render3D(skinImg, capeImg, skin.Render3DOptions{
			Slim:   src.slim,
			Theta:  theta,
			Phi:    playerRenderPhi,
			Time:   playerRenderTime,
			Width:  playerRenderWidth,
			Height: playerRenderHeight,
		})
		return encodeWebP(rendered)
	})
}

// PrecachePlayerRenders eagerly renders a player's front (and back, if they have
// a cape) so the first noscript view is instant. Best-effort.
func (app *App) PrecachePlayerRenders(player *Player) {
	src := app.resolveRenderSource(player)
	if !src.hasSkin {
		return
	}
	if _, err := app.RenderPlayer(player, false); err != nil {
		log.Printf("Error pre-rendering player %s: %s\n", player.Name, err)
	}
	if src.capeID != "none" {
		if _, err := app.RenderPlayer(player, true); err != nil {
			log.Printf("Error pre-rendering player %s (back): %s\n", player.Name, err)
		}
	}
}

// DeletePlayerRendersForSkin removes cached player renders that used a skin
// texture (its hash is the first field of the cache filename).
func (app *App) DeletePlayerRendersForSkin(hash string) error {
	return app.deletePlayerRenderGlob(hash + "_*.webp")
}

// DeletePlayerRendersForCape removes cached player renders that used a cape
// texture (its hash is the middle field of the cache filename).
func (app *App) DeletePlayerRendersForCape(hash string) error {
	return app.deletePlayerRenderGlob("*_" + hash + "_*.webp")
}

func (app *App) deletePlayerRenderGlob(pattern string) error {
	matches, err := filepath.Glob(path.Join(app.Config.StateDirectory, "render", "player", pattern))
	if err != nil {
		return err
	}
	for _, m := range matches {
		if err := app.deleteRender(m); err != nil {
			return err
		}
	}
	return nil
}

// cachedRender returns the render at renderPath, generating and persisting it on
// a cache miss under the FSMutex so a render never runs twice concurrently.
func (app *App) cachedRender(renderPath string, generate func() ([]byte, error)) ([]byte, error) {
	unlock := app.FSMutex.Lock(renderPath)
	defer unlock()

	if cached, err := os.ReadFile(renderPath); err == nil {
		return cached, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	out, err := generate()
	if err != nil {
		return nil, err
	}
	if err := app.writeRender(renderPath, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (app *App) writeRender(renderPath string, data []byte) error {
	if err := os.MkdirAll(path.Dir(renderPath), os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(renderPath, data, 0666)
}

func (app *App) deleteRender(renderPath string) error {
	unlock := app.FSMutex.Lock(renderPath)
	defer unlock()
	if err := os.Remove(renderPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func encodeWebP(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := nativewebp.Encode(&buf, img, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GET /web/render/player/:uuid  (front) and .../back
func FrontRenderPlayer(app *App, back bool) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		player, _, err := app.FindPlayerByUUIDOrOfflineUUID(c.Param("uuid"))
		if err != nil || player == nil {
			return c.NoContent(http.StatusNotFound)
		}

		src := app.resolveRenderSource(player)
		if !src.hasSkin {
			return c.NoContent(http.StatusNotFound)
		}
		view := "front"
		if back {
			view = "back"
		}
		// The render is fully determined by the skin and cape identities, so a
		// changed texture yields a new ETag; revalidate rather than cache hard.
		etag := fmt.Sprintf(`"%s_%s_%s"`, src.skinID, src.capeID, view)
		if c.Request().Header.Get("If-None-Match") == etag {
			return c.NoContent(http.StatusNotModified)
		}

		rendered, err := app.RenderPlayer(player, back)
		if err != nil {
			return err
		}
		c.Response().Header().Set("Cache-Control", "public, no-cache")
		c.Response().Header().Set("ETag", etag)
		return c.Blob(http.StatusOK, "image/webp", rendered)
	}
}

// PlayerHasSkin reports whether the player has anything to render: their own
// skin, an operator default, or a vanilla default (when enabled).
func (app *App) PlayerHasSkin(player *Player) bool {
	return app.resolveRenderSource(player).hasSkin
}

// PlayerBodyRenderURL is the URL of the player's front body render.
func (app *App) PlayerBodyRenderURL(player *Player) (*string, error) {
	if !app.resolveRenderSource(player).hasSkin {
		return nil, nil
	}
	renderURL, err := url.JoinPath(app.FrontEndURL, "web/render/player", player.UUID)
	if err != nil {
		return nil, err
	}
	return &renderURL, nil
}

// PlayerBodyBackRenderURL is the URL of the back "cape view", or nil when the
// player has no cape to show.
func (app *App) PlayerBodyBackRenderURL(player *Player) (*string, error) {
	if app.resolveRenderSource(player).capeID == "none" {
		return nil, nil
	}
	renderURL, err := url.JoinPath(app.FrontEndURL, "web/render/player", player.UUID, "back")
	if err != nil {
		return nil, err
	}
	return &renderURL, nil
}

var vanillaSkinNames = func() map[string]bool {
	names := map[string]bool{}
	for _, vs := range vanillaDefaultSkins {
		names[vs.name] = true
	}
	return names
}()

// FrontVanillaSkin serves a texture from the vanilla-skin directory, so the
// interactive viewer can load a vanilla default for players with no skin.
func FrontVanillaSkin(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		model := c.Param("model")
		name := strings.TrimSuffix(c.Param("name"), ".png")
		if (model != "wide" && model != "slim") || !vanillaSkinNames[name] {
			return c.NoContent(http.StatusNotFound)
		}
		blob, err := os.ReadFile(app.vanillaDefaultSkinPath(vanillaSkin{name: name, slim: model == "slim"}))
		if err != nil {
			return c.NoContent(http.StatusNotFound)
		}
		c.Response().Header().Set("Cache-Control", "public, max-age=86400")
		return c.Blob(http.StatusOK, "image/png", blob)
	}
}

// PlayerViewerSkinURL is the URL of the player's effective skin texture (their
// own, or the resolved default), or nil when there is no skin. PlayerViewerModel
// gives its model.
func (app *App) PlayerViewerSkinURL(player *Player) (*string, error) {
	src := app.resolveRenderSource(player)
	if !src.hasSkin {
		return nil, nil
	}
	if player.SkinHash.Valid {
		return app.PlayerSkinURL(player)
	}
	if strings.HasPrefix(src.skinID, "va-") {
		u, err := uuid.Parse(player.UUID)
		if err != nil {
			return nil, err
		}
		vs := vanillaDefaultSkins[vanillaDefaultSkinIndex(u)]
		skinURL, err := url.JoinPath(app.FrontEndURL, "web/render/vanilla-skin", vanillaSkinModelDir(vs.slim), vs.name+".png")
		if err != nil {
			return nil, err
		}
		return &skinURL, nil
	}
	// Operator default-skin, already served by GetDefaultSkinTexture.
	if tex := app.GetDefaultSkinTexture(player); tex != nil {
		return &tex.URL, nil
	}
	return nil, nil
}

func (app *App) PlayerViewerModel(player *Player) string {
	if app.resolveRenderSource(player).slim {
		return SkinModelSlim
	}
	return SkinModelClassic
}
