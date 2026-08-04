package main

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
)

// The 18 vanilla default skins, in the exact order Minecraft's DefaultPlayerSkin
// declares them (slim variants first, then wide). The client picks one with
// floorMod(uuid.hashCode(), 18); we replicate that so a player with no skin gets
// the same default the vanilla client would draw.
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

const versionManifestURL = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json"

var vanillaSkinsDownloadMutex sync.Mutex

func vanillaSkinModelDir(slim bool) string {
	if slim {
		return "slim"
	}
	return "wide"
}

// javaUUIDHashCode reproduces java.util.UUID.hashCode(), which DefaultPlayerSkin
// uses to select a default skin.
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

func (app *App) GetVanillaDefaultSkinDirectory() string {
	return path.Join(app.Config.StateDirectory, "vanilla-skin")
}

func (app *App) vanillaDefaultSkinPath(skin vanillaSkin) string {
	return path.Join(app.GetVanillaDefaultSkinDirectory(), vanillaSkinModelDir(skin.slim), skin.name+".png")
}

// ensureVanillaDefaultSkins downloads and caches the 18 default skins if they
// aren't already on disk. It's safe to call concurrently.
func (app *App) ensureVanillaDefaultSkins() error {
	if app.vanillaDefaultSkinsCached() {
		return nil
	}

	vanillaSkinsDownloadMutex.Lock()
	defer vanillaSkinsDownloadMutex.Unlock()

	// Another goroutine may have finished while we waited for the lock.
	if app.vanillaDefaultSkinsCached() {
		return nil
	}
	return app.downloadVanillaDefaultSkins()
}

func (app *App) vanillaDefaultSkinsCached() bool {
	for _, skin := range vanillaDefaultSkins {
		if _, err := os.Stat(app.vanillaDefaultSkinPath(skin)); err != nil {
			return false
		}
	}
	return true
}

// httpReaderAt reads a remote file over HTTP range requests, so archive/zip can
// pull just the central directory and the entries we want out of a large jar
// without downloading the whole thing.
type httpReaderAt struct {
	url    string
	client *http.Client
}

// cachingReaderAt coalesces the many small sequential reads archive/zip makes
// (scanning the central directory, reading each entry) into a few large,
// block-aligned range requests, cutting the number of HTTP round-trips.
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
		total += copy(p[total:], block[cur%c.block:])
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

	jarURL, jarSize, err := resolveLatestClientJar(client)
	if err != nil {
		return err
	}
	log.Printf("Downloading vanilla default skins from Mojang (%s)\n", jarURL)

	readerAt := newCachingReaderAt(&httpReaderAt{url: jarURL, client: client}, jarSize)
	zr, err := zip.NewReader(readerAt, jarSize)
	if err != nil {
		return fmt.Errorf("reading client jar zip: %w", err)
	}

	wanted := make(map[string]vanillaSkin, len(vanillaDefaultSkins))
	for _, skin := range vanillaDefaultSkins {
		jarPath := fmt.Sprintf("assets/minecraft/textures/entity/player/%s/%s.png", vanillaSkinModelDir(skin.slim), skin.name)
		wanted[jarPath] = skin
	}

	found := 0
	for _, f := range zr.File {
		skin, ok := wanted[f.Name]
		if !ok {
			continue
		}
		if err := app.extractVanillaSkin(f, skin); err != nil {
			return err
		}
		found++
	}

	if found != len(vanillaDefaultSkins) {
		return fmt.Errorf("expected %d default skins in client jar, found %d", len(vanillaDefaultSkins), found)
	}
	log.Printf("Downloaded %d vanilla default skins to %s\n", found, app.GetVanillaDefaultSkinDirectory())
	return nil
}

func (app *App) extractVanillaSkin(f *zip.File, skin vanillaSkin) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	destPath := app.vanillaDefaultSkinPath(skin)
	if err := os.MkdirAll(path.Dir(destPath), os.ModePerm); err != nil {
		return err
	}
	// Write to a temp file and rename, so a concurrent reader never sees a partial file.
	tmp, err := os.CreateTemp(path.Dir(destPath), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), destPath)
}

// resolveLatestClientJar finds the latest release's client.jar URL and size via
// Mojang's version manifest.
func resolveLatestClientJar(client *http.Client) (string, int64, error) {
	var manifest struct {
		Latest struct {
			Release string `json:"release"`
		} `json:"latest"`
		Versions []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"versions"`
	}
	if err := getJSON(client, versionManifestURL, &manifest); err != nil {
		return "", 0, err
	}

	versionURL := ""
	for _, v := range manifest.Versions {
		if v.ID == manifest.Latest.Release {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return "", 0, fmt.Errorf("latest release %q not found in version manifest", manifest.Latest.Release)
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
		return "", 0, fmt.Errorf("no client download for latest release %q", manifest.Latest.Release)
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
