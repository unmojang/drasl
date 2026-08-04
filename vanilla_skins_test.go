package main

import (
	"bytes"
	"image/png"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestVanillaDefaultSkinIndex(t *testing.T) {
	t.Parallel()

	// Expected indices computed independently from java.util.UUID.hashCode()
	// semantics, so this pins our replication of DefaultPlayerSkin's selection.
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
}

// Network-gated: downloads the latest client jar from Mojang. Run with
// DRASL_TEST_MOJANG_DOWNLOAD=1 go test -run TestDownloadVanillaDefaultSkins .
func TestDownloadVanillaDefaultSkins(t *testing.T) {
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
}
