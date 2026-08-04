package main

import (
	"bytes"
	"image/png"
	"os"
	"path"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestVanillaSkins(t *testing.T) {
	t.Parallel()

	t.Run("Vanilla default skin index", func(t *testing.T) {
		// Computed independently from java.util.UUID.hashCode() semantics.
		cases := map[string]int{
			"00000000-0000-0000-0000-000000000000": 0,
			"f9c8e2a1-4b3d-4e5f-8a9b-0c1d2e3f4a5b": 8,
			"a1b2c3d4-e5f6-7788-99aa-bbccddeeff00": 6,
			"12345678-9abc-def0-1234-567890abcdef": 17,
			"0193b3c9-1a2b-7c3d-8e4f-a5b6c7d8e9fa": 12,
			"cafebabe-0000-0000-1111-222233334444": 2,
		}
		for id, want := range cases {
			got := vanillaDefaultSkinIndex(uuid.MustParse(id))
			assert.Equal(t, want, got, "index for %s", id)
		}
	})

	t.Run("A caching ReaderAt over a short source", func(t *testing.T) {
		inner := bytes.NewReader(make([]byte, 100))
		r := newCachingReaderAt(inner, 1000) // lies: claims 1000 bytes

		buf := make([]byte, 10)
		n, err := r.ReadAt(buf, 150)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)

		n, err = r.ReadAt(buf, 95)
		assert.Equal(t, 5, n)
		assert.NotNil(t, err)
	})

	// Network-gated: downloads the pinned client jar from Mojang. Run with
	// DRASL_TEST_MOJANG_DOWNLOAD=1 go test -run 'TestVanillaSkins/Download' .
	t.Run("Download the vanilla default skins", func(t *testing.T) {
		if os.Getenv("DRASL_TEST_MOJANG_DOWNLOAD") == "" {
			t.Skip("set DRASL_TEST_MOJANG_DOWNLOAD=1 to run the live Mojang download")
		}

		app := &App{Config: &Config{BaseConfig: BaseConfig{
			StateDirectory:            t.TempDir(),
			EnableVanillaDefaultSkins: true,
		}}}

		assert.Nil(t, app.ensureVanillaDefaultSkins())

		for _, skin := range vanillaDefaultSkins {
			data, err := os.ReadFile(app.vanillaDefaultSkinPath(skin))
			assert.Nil(t, err, "%s/%s", vanillaSkinModelDir(skin.slim), skin.name)
			img, err := png.Decode(bytes.NewReader(data))
			assert.Nil(t, err)
			assert.Equal(t, 64, img.Bounds().Dx())
			assert.Equal(t, 64, img.Bounds().Dy())
		}
	})

	{
		ts := &TestSuite{}

		config := testConfig()
		config.EnableVanillaDefaultSkins = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Corrupt cached vanilla default skins are not counted as downloaded", ts.testVanillaDefaultSkinsCachedRejectsCorruptFiles)
	}
}

// A truncated skin left by a crash must not count as downloaded, or the
// download becomes a permanent no-op.
func (ts *TestSuite) testVanillaDefaultSkinsCachedRejectsCorruptFiles(t *testing.T) {
	for _, skin := range vanillaDefaultSkins {
		p := ts.App.vanillaDefaultSkinPath(skin)
		assert.Nil(t, os.MkdirAll(path.Dir(p), os.ModePerm))
		assert.Nil(t, os.WriteFile(p, RED_SKIN, 0666))
	}
	assert.True(t, ts.App.vanillaDefaultSkinsCached())

	truncated := ts.App.vanillaDefaultSkinPath(vanillaDefaultSkins[3])
	assert.Nil(t, os.WriteFile(truncated, RED_SKIN[:20], 0666))
	assert.False(t, ts.App.vanillaDefaultSkinsCached())

	assert.Nil(t, os.WriteFile(truncated, nil, 0666))
	assert.False(t, ts.App.vanillaDefaultSkinsCached())
}
