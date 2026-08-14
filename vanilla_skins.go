package main

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

// The 18 vanilla defaults in DefaultPlayerSkin's exact order (slim, then wide):
// the client picks floorMod(uuid.hashCode(), 18), and we must agree with it.
type vanillaSkin struct {
	name string
	slim bool
}

var vanillaDefaultSkins = []vanillaSkin{
	{"alex", true}, {"ari", true}, {"efe", true}, {"kai", true}, {"makena", true},
	{"noor", true}, {"steve", true}, {"sunny", true}, {"zuri", true},
	{"alex", false}, {"ari", false}, {"efe", false}, {"kai", false}, {"makena", false},
	{"noor", false}, {"steve", false}, {"sunny", false}, {"zuri", false},
}

const VERSION_MANIFEST_URL = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json"

const VANILLA_SKINS_VERSION = "26.2"

var vanillaSkinsDownloadMutex sync.Mutex

func vanillaSkinModelDir(slim bool) string {
	if slim {
		return "slim"
	}
	return "wide"
}

// java.util.UUID.hashCode(), which DefaultPlayerSkin selects with.
func javaUUIDHashCode(u uuid.UUID) int32 {
	msb := int64(binary.BigEndian.Uint64(u[0:8]))
	lsb := int64(binary.BigEndian.Uint64(u[8:16]))
	hilo := msb ^ lsb
	return int32(hilo>>32) ^ int32(hilo)
}

func vanillaDefaultSkinIndex(u uuid.UUID) int {
	n := int32(len(vanillaDefaultSkins))
	mod := javaUUIDHashCode(u) % n
	if mod < 0 {
		mod += n
	}
	return int(mod)
}

var vanillaSkinNames = func() map[string]bool {
	names := map[string]bool{}
	for _, vs := range vanillaDefaultSkins {
		names[vs.name] = true
	}
	return names
}()

// The default the client draws for a player with no skin. The game leaves this
// to the client, so it is a preview concern only.
func (app *App) VanillaDefaultSkin(player *Player) (*string, bool, error) {
	if !app.Config.EnableVanillaDefaultSkins {
		return nil, false, nil
	}
	u, err := uuid.Parse(player.UUID)
	if err != nil {
		return nil, false, err
	}
	skin := vanillaDefaultSkins[vanillaDefaultSkinIndex(u)]
	// They download asynchronously; a preview that misses them re-arms it.
	if _, err := os.Stat(app.vanillaDefaultSkinPath(skin)); err != nil {
		app.retryVanillaDefaultSkinsAsync()
		return nil, false, nil
	}
	skinURL, err := url.JoinPath(app.FrontEndURL, "web/vanilla-skin", vanillaSkinModelDir(skin.slim), skin.name+".png")
	if err != nil {
		return nil, false, err
	}
	return &skinURL, skin.slim, nil
}

// GET /web/vanilla-skin/:model/:name
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
		c.Response().Header().Set("Cache-Control", "private, max-age=86400")
		return c.Blob(http.StatusOK, "image/png", blob)
	}
}

func (app *App) GetVanillaDefaultSkinDirectory() string {
	return path.Join(app.Config.StateDirectory, "vanilla-skin")
}

func (app *App) vanillaDefaultSkinPath(skin vanillaSkin) string {
	return path.Join(app.GetVanillaDefaultSkinDirectory(), vanillaSkinModelDir(skin.slim), skin.name+".png")
}

// Retried because this runs at boot, when egress or DNS may not be up yet.
const VANILLA_DEFAULT_SKIN_DOWNLOAD_ATTEMPTS = 3

func (app *App) ensureVanillaDefaultSkinsWithRetry() {
	for attempt := 1; ; attempt++ {
		err := app.ensureVanillaDefaultSkins()
		if err == nil {
			return
		}
		if attempt >= VANILLA_DEFAULT_SKIN_DOWNLOAD_ATTEMPTS {
			log.Printf("Giving up downloading vanilla default skins after %d attempts: %s\n", attempt, err)
			log.Printf("The download will be retried when a preview needs them. Set EnableVanillaDefaultSkins=false to disable this.\n")
			return
		}
		log.Printf("Error downloading vanilla default skins (attempt %d): %s\n", attempt, err)
		time.Sleep(time.Duration(attempt) * 30 * time.Second)
	}
}

const VANILLA_DEFAULT_SKIN_RETRY_INTERVAL = 5 * time.Minute

// Whether we won the one attempt allowed per interval for this key.
func (app *App) armThrottle(key string, ttl time.Duration) bool {
	if _, found := app.RequestCache.Get(key); found {
		return false
	}
	app.RequestCache.SetWithTTL(key, struct{}{}, 0, ttl)
	app.RequestCache.Wait()
	return true
}

// A failed startup download must not break previews until a restart.
func (app *App) retryVanillaDefaultSkinsAsync() {
	if DRASL_TEST() {
		return
	}
	if !app.armThrottle("vanilla-default-skins-retry", VANILLA_DEFAULT_SKIN_RETRY_INTERVAL) {
		return
	}
	goRecovered("downloading vanilla default skins", func() {
		if err := app.ensureVanillaDefaultSkins(); err != nil {
			log.Printf("Error downloading vanilla default skins: %s\n", err)
		}
	})
}

// Safe to call concurrently.
func (app *App) ensureVanillaDefaultSkins() error {
	if app.vanillaDefaultSkinsCached() {
		return nil
	}

	vanillaSkinsDownloadMutex.Lock()
	defer vanillaSkinsDownloadMutex.Unlock()

	if app.vanillaDefaultSkinsCached() {
		return nil
	}
	return app.downloadVanillaDefaultSkins()
}

func (app *App) vanillaDefaultSkinsCached() bool {
	for _, skin := range vanillaDefaultSkins {
		f, err := os.Open(app.vanillaDefaultSkinPath(skin))
		if err != nil {
			return false
		}
		_, err = png.DecodeConfig(f)
		f.Close()
		if err != nil {
			return false
		}
	}
	return true
}

// Reads a remote file via HTTP range requests, so archive/zip can pull just
// the entries we want out of a large jar.
type httpReaderAt struct {
	url    string
	client *http.Client
}

// Coalesces archive/zip's many small reads into a few block-aligned ones.
type cachingReaderAt struct {
	inner io.ReaderAt
	size  int64
	block int64
	mu    sync.Mutex
	cache map[int64][]byte
}

func newCachingReaderAt(inner io.ReaderAt, size int64) *cachingReaderAt {
	return &cachingReaderAt{inner: inner, size: size, block: 256 * 1024, cache: map[int64][]byte{}}
}

func (c *cachingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= c.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) {
		cur := off + int64(total)
		if cur >= c.size {
			return total, io.EOF
		}
		block, err := c.getBlock(cur - cur%c.block)
		if err != nil {
			return total, err
		}
		// A block short of its declared size would otherwise panic on the index
		// below, or never advance the loop.
		offset := cur % c.block
		if offset >= int64(len(block)) {
			return total, io.ErrUnexpectedEOF
		}
		total += copy(p[total:], block[offset:])
	}
	return total, nil
}

func (c *cachingReaderAt) getBlock(blockOff int64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.cache[blockOff]; ok {
		return b, nil
	}
	length := c.block
	if blockOff+length > c.size {
		length = c.size - blockOff
	}
	buf := make([]byte, length)
	n, err := c.inner.ReadAt(buf, blockOff)
	if err != nil && err != io.EOF {
		return nil, err
	}
	buf = buf[:n]
	c.cache[blockOff] = buf
	return buf, nil
}

func (r *httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1))
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("range request to %s returned status %d", r.url, resp.StatusCode)
	}
	n, err := io.ReadFull(resp.Body, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

func (app *App) downloadVanillaDefaultSkins() error {
	client := &http.Client{Timeout: 60 * time.Second}

	jarURL, jarSize, err := resolvePinnedClientJar(client)
	if err != nil {
		return err
	}
	log.Printf("Downloading vanilla default skins from Mojang (%s)\n", jarURL)

	readerAt := newCachingReaderAt(&httpReaderAt{url: jarURL, client: client}, jarSize)
	zr, err := zip.NewReader(readerAt, jarSize)
	if err != nil {
		return fmt.Errorf("reading client jar zip: %w", err)
	}

	for _, skin := range vanillaDefaultSkins {
		jarPath := fmt.Sprintf("assets/minecraft/textures/entity/player/%s/%s.png", vanillaSkinModelDir(skin.slim), skin.name)
		rc, err := zr.Open(jarPath)
		if err != nil {
			return fmt.Errorf("extracting %s from client jar: %w", jarPath, err)
		}
		err = app.extractVanillaSkin(rc, skin)
		rc.Close()
		if err != nil {
			return fmt.Errorf("extracting %s from client jar: %w", jarPath, err)
		}
	}
	log.Printf("Downloaded %d vanilla default skins to %s\n", len(vanillaDefaultSkins), app.GetVanillaDefaultSkinDirectory())
	return nil
}

// Rename, or a crash mid-write leaves a truncated file that the cache check
// would accept.
func writeFileAtomic(destPath string, data []byte) error {
	if err := os.MkdirAll(path.Dir(destPath), os.ModePerm); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(path.Dir(destPath), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), destPath)
}

func (app *App) extractVanillaSkin(r io.Reader, skin vanillaSkin) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(app.vanillaDefaultSkinPath(skin), data)
}

func resolvePinnedClientJar(client *http.Client) (string, int64, error) {
	var manifest struct {
		Versions []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"versions"`
	}
	if err := getJSON(client, VERSION_MANIFEST_URL, &manifest); err != nil {
		return "", 0, err
	}

	versionURL := ""
	for _, v := range manifest.Versions {
		if v.ID == VANILLA_SKINS_VERSION {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return "", 0, fmt.Errorf("version %q not found in version manifest", VANILLA_SKINS_VERSION)
	}

	var version struct {
		Downloads struct {
			Client struct {
				URL  string `json:"url"`
				Size int64  `json:"size"`
			} `json:"client"`
		} `json:"downloads"`
	}
	if err := getJSON(client, versionURL, &version); err != nil {
		return "", 0, err
	}
	if version.Downloads.Client.URL == "" || version.Downloads.Client.Size == 0 {
		return "", 0, fmt.Errorf("no client download for version %q", VANILLA_SKINS_VERSION)
	}
	return version.Downloads.Client.URL, version.Downloads.Client.Size, nil
}

func getJSON(client *http.Client, url string, v any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
