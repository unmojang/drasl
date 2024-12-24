package main

import (
	"errors"
	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"os"
	"testing"
)

func (ts *TestSuite) getFreshDatabase(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	assert.Nil(t, err)
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
	assert.Equal(t, 1, len(v4User.Players))
	player := v4User.Players[0]
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
	assert.Equal(t, 1, len(v4foo.Players))
	assert.Equal(t, "foo", v4foo.Players[0].Name)

	var v4qux V4User
	assert.Nil(t, db.First(&v4qux, "username = ?", "qux").Error)
	assert.Equal(t, 1, len(v4qux.Players))
	assert.Equal(t, "qux", v4qux.Players[0].Name)
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

func (ts *TestSuite) testMigrateBackwards(t *testing.T) {
	db := ts.getFreshDatabase(t)

	query, err := os.ReadFile("sql/1.sql")
	assert.Nil(t, err)
	assert.Nil(t, db.Exec(string(query)).Error)
	setUserVersion(db, CURRENT_USER_VERSION+1)

	err = Migrate(ts.Config, mo.None[string](), db, true, CURRENT_USER_VERSION)
	var backwardsMigrationError BackwardsMigrationError
	assert.True(t, errors.As(err, &backwardsMigrationError))
}
