package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func (ts *TestSuite) getFreshDatabase(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	assert.Nil(t, err)
	assert.Nil(t, db.Exec("PRAGMA busy_timeout = 5000").Error)
	return db
}

func TestDB(t *testing.T) {
	t.Parallel()
	ts := TestSuite{}

	log.SetOutput(io.Discard)

	tempStateDirectory := Unwrap(os.MkdirTemp("", "tmp"))
	ts.StateDirectory = tempStateDirectory

	config := DefaultConfig()
	config.StateDirectory = tempStateDirectory
	config.DataDirectory = "."
	ts.Config = &config

	defer ts.Teardown()

	t.Run("Test with a fresh database", ts.testFreshDatabase)
	t.Run("Test 1->2 migration", ts.testMigrate1To2)
	t.Run("Test 2->3 migration", ts.testMigrate2To3)
	t.Run("Test 3->4 migration", ts.testMigrate3To4)
	t.Run("Test 3->4 migration, username/player name collision", ts.testMigrate3To4Collision)
	t.Run("Test 3->4 migration, empty database", ts.testMigrate3To4Empty)
	t.Run("Test 4->5 migration", ts.testMigrate4To5)
	t.Run("Test 4->5 migration, many clients", ts.testMigrate4To5ManyClients)
	t.Run("Test 5->6 migration", ts.testMigrate5To6)
	t.Run("Test backwards migration", ts.testMigrateBackwards)
}

func (ts *TestSuite) testFreshDatabase(t *testing.T) {
	db := ts.getFreshDatabase(t)
	err := Migrate(ts.Config, mo.None[string](), db, false, CURRENT_USER_VERSION)
	assert.Nil(t, err)
}

func (ts *TestSuite) testMigrate1To2(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/1.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var v1Client V1Client
	assert.Nil(t, db.First(&v1Client).Error)

	err = Migrate(ts.Config, mo.None[string](), db, true, 2)
	assert.Nil(t, err)

	var v2Client V2Client
	assert.Nil(t, db.First(&v2Client).Error)
	assert.NotEqual(t, "", v2Client.UUID)
	assert.Equal(t, v1Client.UserUUID, v2Client.UserUUID)
	assert.Equal(t, v1Client.Version, v2Client.Version)
}

func (ts *TestSuite) testMigrate2To3(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/2.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var v2User V2User
	assert.Nil(t, db.First(&v2User).Error)

	err = Migrate(ts.Config, mo.None[string](), db, true, 3)
	assert.Nil(t, err)

	var v3User V3User
	assert.Nil(t, db.First(&v3User).Error)
	assert.NotEqual(t, "", v3User.APIToken)
}

func (ts *TestSuite) testMigrate3To4(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/3.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var v3User V3User
	assert.Nil(t, db.First(&v3User).Error)

	err = Migrate(ts.Config, mo.None[string](), db, true, 4)
	assert.Nil(t, err)

	var v4User V4User
	assert.Nil(t, db.First(&v4User).Error)
	var player V4Player
	assert.Nil(t, db.First(&player).Error)
	assert.NotEqual(t, v3User.UUID, v4User.UUID)
	assert.Equal(t, v3User.UUID, player.UUID)
	assert.Equal(t, v3User.OfflineUUID, player.OfflineUUID)
	assert.Equal(t, *UnmakeNullString(&v3User.SkinHash), *UnmakeNullString(&player.SkinHash))
	assert.Equal(t, *UnmakeNullString(&v3User.CapeHash), *UnmakeNullString(&player.CapeHash))
}

func (ts *TestSuite) testMigrate3To4Collision(t *testing.T) {
	// User foo has player qux
	// User qux has player foo
	// After migration, user foo should have player foo and user qux should
	// have player qux

	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/3-username-player-name-collison.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var v3foo V3User
	assert.Nil(t, db.First(&v3foo, "username = ?", "foo").Error)
	assert.Equal(t, "qux", v3foo.PlayerName)

	var v3qux V3User
	assert.Nil(t, db.First(&v3qux, "username = ?", "qux").Error)
	assert.Equal(t, "foo", v3qux.PlayerName)

	err = Migrate(ts.Config, mo.None[string](), db, true, 4)
	assert.Nil(t, err)

	var v4foo V4User
	assert.Nil(t, db.First(&v4foo, "username = ?", "foo").Error)
	var v4fooPlayers []V4Player
	assert.Nil(t, db.Where("user_uuid = ?", v4foo.UUID).Find(&v4fooPlayers).Error)
	assert.Equal(t, 1, len(v4fooPlayers))
	assert.Equal(t, "foo", v4fooPlayers[0].Name)

	var v4qux V4User
	assert.Nil(t, db.First(&v4qux, "username = ?", "qux").Error)
	var v4quxPlayers []V4Player
	assert.Nil(t, db.Where("user_uuid = ?", v4qux.UUID).Find(&v4quxPlayers).Error)
	assert.Equal(t, 1, len(v4quxPlayers))
	assert.Equal(t, "qux", v4quxPlayers[0].Name)
}

func (ts *TestSuite) testMigrate3To4Empty(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/3-empty.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var users []User
	assert.Nil(t, db.Find(&users).Error)
	assert.Equal(t, 0, len(users))

	err = Migrate(ts.Config, mo.None[string](), db, true, 4)
	assert.Nil(t, err)
}

func (ts *TestSuite) testMigrate4To5(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/4.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	err = Migrate(ts.Config, mo.None[string](), db, true, 5)
	assert.Nil(t, err)
}

func (ts *TestSuite) testMigrate4To5ManyClients(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/4-many-clients.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	var users []User
	assert.Nil(t, db.Find(&users).Error)
	assert.Equal(t, 4, len(users))

	var foo User
	assert.Nil(t, db.First(&foo, "username = ?", "foo").Error)
	var bar User
	assert.Nil(t, db.First(&bar, "username = ?", "bar").Error)
	var baz User
	assert.Nil(t, db.First(&baz, "username = ?", "baz").Error)
	var qux User
	assert.Nil(t, db.First(&qux, "username = ?", "qux").Error)

	var fooClients []Client
	assert.Nil(t, db.Where("user_uuid = ?", foo.UUID).Find(&fooClients).Error)
	assert.True(t, len(fooClients) > Constants.MaxClientCount)

	var barClients []Client
	assert.Nil(t, db.Where("user_uuid = ?", bar.UUID).Find(&barClients).Error)
	assert.True(t, len(barClients) > Constants.MaxClientCount)

	var bazClients []Client
	assert.Nil(t, db.Where("user_uuid = ?", baz.UUID).Find(&bazClients).Error)
	assert.Equal(t, 1, len(bazClients))

	var quxClients []Client
	assert.Nil(t, db.Where("user_uuid = ?", qux.UUID).Find(&quxClients).Error)
	assert.Equal(t, 0, len(quxClients))

	err = Migrate(ts.Config, mo.None[string](), db, true, 5)
	assert.Nil(t, err)

	assert.Nil(t, db.Where("user_uuid = ?", foo.UUID).Find(&fooClients).Error)
	assert.Equal(t, Constants.MaxClientCount, len(fooClients))

	assert.Nil(t, db.Where("user_uuid = ?", bar.UUID).Find(&barClients).Error)
	assert.Equal(t, Constants.MaxClientCount, len(barClients))

	assert.Nil(t, db.Where("user_uuid = ?", baz.UUID).Find(&bazClients).Error)
	assert.Equal(t, 1, len(bazClients))

	assert.Nil(t, db.Where("user_uuid = ?", qux.UUID).Find(&quxClients).Error)
	assert.Equal(t, 0, len(quxClients))
}

func (ts *TestSuite) testMigrateBackwards(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/1.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)
	assert.Nil(t, setUserVersion(db, CURRENT_USER_VERSION+1))

	err = Migrate(ts.Config, mo.None[string](), db, true, CURRENT_USER_VERSION)
	var backwardsMigrationError BackwardsMigrationError
	assert.True(t, errors.As(err, &backwardsMigrationError))
}

func (ts *TestSuite) testMigrate5To6(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/5.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)

	// BLAKE3 hashes of RED_SKIN / RED_CAPE, as stored in 5.sql
	redSkinB3Sum := "27818f0eadf68945ad0880c6c63c2baa0f466ac41960b3b6cc00c51e5dd23125"
	redCapeB3Sum := "d69e2c4c5dac0575f1c95805778d66e11e31996199a8f32381062d0ac00b240d"

	// Create the skin/cape directories and write the textures under their
	// BLAKE3-named filenames, mirroring the on-disk state of a v5 instance.
	skinDir := filepath.Join(ts.StateDirectory, "skin")
	capeDir := filepath.Join(ts.StateDirectory, "cape")
	assert.Nil(t, os.MkdirAll(skinDir, 0755))
	assert.Nil(t, os.MkdirAll(capeDir, 0755))

	skinB3Path := filepath.Join(skinDir, redSkinB3Sum+".png")
	capeB3Path := filepath.Join(capeDir, redCapeB3Sum+".png")
	assert.Nil(t, os.WriteFile(skinB3Path, RED_SKIN, 0644))
	assert.Nil(t, os.WriteFile(capeB3Path, RED_CAPE, 0644))

	// Sanity: confirm the DB holds the BLAKE3 hashes before migration.
	var playerBefore V5Player
	assert.Nil(t, db.First(&playerBefore, "name = ?", "foo").Error)
	skinHashBefore, ok := NullStringToOption(&playerBefore.SkinHash).Get()
	assert.True(t, ok)
	assert.Equal(t, redSkinB3Sum, skinHashBefore)
	capeHashBefore, ok := NullStringToOption(&playerBefore.CapeHash).Get()
	assert.True(t, ok)
	assert.Equal(t, redCapeB3Sum, capeHashBefore)

	// Sanity: confirm a v5 client row exists before migration.
	var clientBefore V5Client
	assert.Nil(t, db.First(&clientBefore).Error)

	err = Migrate(ts.Config, mo.None[string](), db, true, 6)
	assert.Nil(t, err)

	// The BLAKE3-named files should be gone, replaced by SHA256-named files.
	_, err = os.Stat(skinB3Path)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(capeB3Path)
	assert.True(t, os.IsNotExist(err))

	skinSha256Path := filepath.Join(skinDir, RED_SKIN_HASH+".png")
	capeSha256Path := filepath.Join(capeDir, RED_CAPE_HASH+".png")
	skinContents, err := os.ReadFile(skinSha256Path)
	assert.Nil(t, err)
	assert.Equal(t, RED_SKIN, skinContents)
	capeContents, err := os.ReadFile(capeSha256Path)
	assert.Nil(t, err)
	assert.Equal(t, RED_CAPE, capeContents)

	// The DB should now reference the SHA256 hashes.
	var playerAfter V6Player
	assert.Nil(t, db.First(&playerAfter, "name = ?", "foo").Error)
	skinHashAfter, ok := NullStringToOption(&playerAfter.SkinHash).Get()
	assert.True(t, ok)
	assert.Equal(t, RED_SKIN_HASH, skinHashAfter)
	capeHashAfter, ok := NullStringToOption(&playerAfter.CapeHash).Get()
	assert.True(t, ok)
	assert.Equal(t, RED_CAPE_HASH, capeHashAfter)

	// The migration should have added the auth_method column, backfilling
	// existing rows with AuthMethodUnknown (0).
	var clientAfter Client
	assert.Nil(t, db.First(&clientAfter).Error)
	assert.Equal(t, AuthMethodUnknown, clientAfter.AuthMethod)

	// Recompute SHA256 of the on-disk files to confirm the recorded hashes
	// match the actual file contents.
	skinSum := sha256.Sum256(skinContents)
	assert.Equal(t, RED_SKIN_HASH, hex.EncodeToString(skinSum[:]))
	capeSum := sha256.Sum256(capeContents)
	assert.Equal(t, RED_CAPE_HASH, hex.EncodeToString(capeSum[:]))
}
