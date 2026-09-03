package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/samber/mo"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const CURRENT_USER_VERSION = 7

const PLAYER_NAME_TAKEN_BY_USERNAME_ERROR = "PLAYER_NAME_TAKEN_BY_USERNAME"
const USERNAME_TAKEN_BY_PLAYER_NAME_ERROR = "USERNAME_TAKEN_BY_PLAYER_NAME"

type Error error

func IsErrorUniqueFailed(err error) bool {
	if err == nil {
		return false
	}
	// Work around https://stackoverflow.com/questions/75489773/why-do-i-get-second-argument-to-errors-as-should-not-be-error-build-error-in
	e := (errors.New("UNIQUE constraint failed")).(Error)
	return errors.As(err, &e)
}

func IsErrorUniqueFailedField(err error, field string) bool {
	if err == nil {
		return false
	}

	// The Go programming language 😎
	return err.Error() == "UNIQUE constraint failed: "+field
}

func IsErrorUsernameTakenByPlayerName(err error) bool {
	return err.Error() == USERNAME_TAKEN_BY_PLAYER_NAME_ERROR
}

func IsErrorPlayerNameTakenByUsername(err error) bool {
	return err.Error() == PLAYER_NAME_TAKEN_BY_USERNAME_ERROR
}

type BackwardsMigrationError struct {
	Err error
}

func (e BackwardsMigrationError) Error() string {
	return e.Err.Error()
}

type V1User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string     `gorm:"primaryKey"`
	Username          string     `gorm:"unique;not null"`
	PasswordSalt      []byte     `gorm:"not null"`
	PasswordHash      []byte     `gorm:"not null"`
	Clients           []V1Client `gorm:"foreignKey:UserUUID"`
	ServerID          sql.NullString
	PlayerName        string `gorm:"unique;not null;type:text collate nocase"`
	FallbackPlayer    string
	PreferredLanguage string
	BrowserToken      sql.NullString `gorm:"index"`
	APIToken          string
	SkinHash          sql.NullString `gorm:"index"`
	SkinModel         string
	CapeHash          sql.NullString `gorm:"index"`
	CreatedAt         time.Time
	NameLastChangedAt time.Time
}

func (V1User) TableName() string {
	return "users"
}

type V1Client struct {
	ClientToken string `gorm:"primaryKey"`
	Version     int
	UserUUID    string
	User        V3User
}

func (V1Client) TableName() string {
	return "clients"
}

type V2User = V1User

type V2Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string
	User        V2User `gorm:"foreignKey:UserUUID"`
}

func (V2Client) TableName() string {
	return "clients"
}

type V3User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string     `gorm:"primaryKey"`
	Username          string     `gorm:"unique;not null"`
	PasswordSalt      []byte     `gorm:"not null"`
	PasswordHash      []byte     `gorm:"not null"`
	Clients           []V3Client `gorm:"foreignKey:UserUUID"`
	ServerID          sql.NullString
	PlayerName        string `gorm:"unique;not null;type:text collate nocase"`
	OfflineUUID       string `gorm:"not null"`
	FallbackPlayer    string
	PreferredLanguage string
	BrowserToken      sql.NullString `gorm:"index"`
	APIToken          string
	SkinHash          sql.NullString `gorm:"index"`
	SkinModel         string
	CapeHash          sql.NullString `gorm:"index"`
	CreatedAt         time.Time
	NameLastChangedAt time.Time
}

func (V3User) TableName() string {
	return "users"
}

type V3Client = V2Client

type V4User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string `gorm:"primaryKey"`
	Username          string `gorm:"unique;not null"`
	PasswordSalt      []byte
	PasswordHash      []byte
	BrowserToken      sql.NullString `gorm:"index"`
	MinecraftToken    string
	APIToken          string
	PreferredLanguage string
	Players           []V4Player `gorm:"foreignKey:UserUUID"`
	MaxPlayerCount    int
	Clients           []V4Client           `gorm:"foreignKey:UserUUID"`
	OIDCIdentities    []V4UserOIDCIdentity `gorm:"foreignKey:UserUUID"`
}

func (V4User) TableName() string {
	return "users"
}

type V4Player struct {
	UUID              string `gorm:"primaryKey"`
	Name              string `gorm:"unique;not null;type:text collate nocase"`
	OfflineUUID       string `gorm:"not null"`
	CreatedAt         time.Time
	NameLastChangedAt time.Time
	SkinHash          sql.NullString `gorm:"index"`
	SkinModel         string
	CapeHash          sql.NullString `gorm:"index"`
	ServerID          sql.NullString
	FallbackPlayer    string
	User              V4User
	UserUUID          string     `gorm:"not null"`
	Clients           []V4Client `gorm:"foreignKey:PlayerUUID;constraint:OnDelete:CASCADE"`
}

func (V4Player) TableName() string {
	return "players"
}

type V4Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string `gorm:"not null"`
	User        V4User
	PlayerUUID  sql.NullString `gorm:"index"`
	Player      *V4Player
}

func (V4Client) TableName() string {
	return "clients"
}

type V4UserOIDCIdentity struct {
	ID       uint `gorm:"primaryKey"`
	User     V4User
	UserUUID string `gorm:"index;not null"`
	Subject  string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
	Issuer   string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
}

type V6User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string `gorm:"primaryKey"`
	Username          string `gorm:"unique;not null"`
	PasswordSalt      []byte
	PasswordHash      []byte
	BrowserToken      sql.NullString `gorm:"index"`
	MinecraftToken    string
	APIToken          string
	PreferredLanguage string
	Players           []V6Player `gorm:"foreignKey:UserUUID"`
	MaxPlayerCount    int
	Clients           []V6Client           `gorm:"foreignKey:UserUUID"`
	OIDCIdentities    []V6UserOIDCIdentity `gorm:"foreignKey:UserUUID"`
}

func (V6User) TableName() string {
	return "users"
}

type V6Player struct {
	UUID              string `gorm:"primaryKey"`
	Name              string `gorm:"unique;not null;type:text collate nocase"`
	OfflineUUID       string `gorm:"not null"`
	CreatedAt         time.Time
	NameLastChangedAt time.Time
	SkinHash          sql.NullString `gorm:"index"`
	SkinModel         string
	CapeHash          sql.NullString `gorm:"index"`
	ServerID          sql.NullString
	FallbackPlayer    string
	User              V6User
	UserUUID          string     `gorm:"not null"`
	Clients           []V6Client `gorm:"foreignKey:PlayerUUID;constraint:OnDelete:CASCADE"`
}

func (V6Player) TableName() string {
	return "players"
}

type V6Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string `gorm:"not null"`
	User        V6User
	PlayerUUID  sql.NullString `gorm:"index"`
	Player      *V6Player
	LastUsedAt  time.Time
	AuthMethod  AuthMethod
}

func (V6Client) TableName() string {
	return "clients"
}

type V6UserOIDCIdentity struct {
	ID       uint `gorm:"primaryKey"`
	User     V6User
	UserUUID string `gorm:"index;not null"`
	Subject  string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
	Issuer   string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
}

func (V6UserOIDCIdentity) TableName() string {
	return "user_oidc_identities"
}

type V5User = V6User
type V5Player = V6Player
type V5Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string `gorm:"not null"`
	User        V5User
	PlayerUUID  sql.NullString `gorm:"index"`
	Player      *V5Player
	LastUsedAt  time.Time
}

func (V5Client) TableName() string {
	return "clients"
}

type V5UserOIDCIdentity = V6UserOIDCIdentity

func OpenDB(config *Config) (*gorm.DB, error) {
	dbPath := path.Join(config.StateDirectory, "drasl.db")
	_, err := os.Stat(dbPath)
	alreadyExisted := err == nil

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_synchronous=NORMAL&_txlock=immediate", dbPath)
	db := Unwrap(gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}))

	err = Migrate(config, mo.Some(dbPath), db, alreadyExisted, CURRENT_USER_VERSION)
	if err != nil {
		return nil, fmt.Errorf("Error migrating database: %w", err)
	}

	return db, nil
}

func setUserVersion(tx *gorm.DB, userVersion uint) error {
	// PRAGMA user_version = ? doesn't work here
	return tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", userVersion)).Error
}

func Migrate(config *Config, dbPath mo.Option[string], db *gorm.DB, alreadyExisted bool, targetUserVersion uint) error {
	var userVersion uint

	if alreadyExisted {
		if err := db.Raw("PRAGMA user_version;").Scan(&userVersion).Error; err != nil {
			return nil
		}
	} else {
		userVersion = targetUserVersion
	}

	initialUserVersion := userVersion
	if initialUserVersion > targetUserVersion {
		return BackwardsMigrationError{
			Err: fmt.Errorf("Database is version %d, migration target version is %d, cannot continue. Are you trying to run an older version of %s with a newer database?", userVersion, targetUserVersion, config.ApplicationName),
		}
	}

	if initialUserVersion < targetUserVersion {
		log.Printf("Started migration of database version %d to %d.", userVersion, targetUserVersion)
		if !config.PreMigrationBackups {
			log.Printf("PreMigrationBackups disabled, skipping backup.")
		} else if p, ok := dbPath.Get(); ok {
			if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
				return fmt.Errorf("Error checkpointing WAL before backup: %w", err)
			}
			dbDir := filepath.Dir(p)
			datetime := time.Now().UTC().Format("2006-01-02T15-04-05Z")
			backupPath := path.Join(dbDir, fmt.Sprintf("drasl.%d.%s.db", userVersion, datetime))
			log.Printf("Backing up old database to %s", backupPath)
			_, err := CopyPath(p, backupPath)
			if err != nil {
				return fmt.Errorf("Error backing up database: %w", err)
			}
			log.Printf("Database backed up, proceeding.")
		} else {
			log.Printf("Database path not specified, skipping backup.")
		}
	}

	unusedTexturePaths := make([]string, 0, 0)

	err := db.Transaction(func(tx *gorm.DB) error {
		if userVersion == 0 && targetUserVersion >= 1 {
			// Version 0 to 1
			// Add User.OfflineUUID
			if err := tx.AutoMigrate(&V1User{}); err != nil {
				return err
			}
			var users []V1User
			if err := tx.Find(&users).Error; err != nil {
				return err
			}
			for _, user := range users {
				offlineUUID, err := OfflineUUID(user.PlayerName)
				if err != nil {
					return err
				}
				if err := tx.Model(&user).Update("offline_uuid", offlineUUID).Error; err != nil {
					return err
				}
			}
			userVersion += 1
		}
		if userVersion == 1 && targetUserVersion >= 2 {
			// Version 1 to 2
			// Change Client primaryKey from ClientToken to UUID
			if err := tx.Exec("ALTER TABLE clients RENAME client_token TO uuid").Error; err != nil {
				return err
			}
			if err := tx.Migrator().AddColumn(&V2Client{}, "client_token"); err != nil {
				return err
			}
			if err := tx.Exec("UPDATE clients SET client_token = uuid").Error; err != nil {
				return err
			}
			userVersion += 1
		}
		if userVersion == 2 && targetUserVersion >= 3 {
			// Version 2 to 3
			// Add User.APIToken

			if err := tx.Migrator().AddColumn(&V3User{}, "api_token"); err != nil {
				return err
			}
			var users []V3User
			if err := tx.Find(&users).Error; err != nil {
				return err
			}
			for _, user := range users {
				apiToken, err := MakeAPIToken()
				if err != nil {
					return err
				}
				if err := tx.Model(&user).Update("api_token", apiToken).Error; err != nil {
					return err
				}
			}
			userVersion += 1
		}
		if userVersion == 3 && targetUserVersion >= 4 {
			// Version 3 to 4
			// Split Users and Players. We will replace each user's UUID (their
			// primary key) with a new random one to avoid confusion between
			// user UUIDs and player UUIDs. The easiest way to do this is to
			// load all users into memory, remove them from the DB, then
			// re-insert them. This is bad, and in the future we should (1)
			// avoid changing primary keys at all and (2) perform migrations
			// like this either entirely in SQL or in batches.

			var v3Users []V3User
			if err := tx.Preload("Clients").Find(&v3Users).Error; err != nil {
				return err
			}

			if err := tx.Exec(`
				DROP TABLE users;
				DROP TABLE clients;
			`).Error; err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V4User{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V4Player{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V4Client{}); err != nil {
				return err
			}

			allUsernames := mapset.NewSet[string]()
			for _, v3User := range v3Users {
				allUsernames.Add(v3User.Username)
			}

			users := make([]V4User, 0, len(v3Users))
			for _, v3User := range v3Users {
				newUUID := uuid.New().String()
				clients := make([]V4Client, 0, len(v3User.Clients))
				for _, v3Client := range v3User.Clients {
					clients = append(clients, V4Client{
						UUID:        v3Client.UUID,
						ClientToken: v3Client.ClientToken,
						Version:     v3Client.Version,
						UserUUID:    newUUID,
						PlayerUUID:  MakeNullString(&v3Client.UserUUID),
					})
				}
				// If the player name is in use as someone else's username,
				// reset the player name to its owner's username
				playerName := v3User.PlayerName
				if playerName != v3User.Username && allUsernames.Contains(playerName) {
					playerName = v3User.Username
				}
				minecraftPassword, err := MakeMinecraftToken()
				if err != nil {
					return err
				}
				player := V4Player{
					UUID:              v3User.UUID,
					Name:              playerName,
					OfflineUUID:       v3User.OfflineUUID,
					CreatedAt:         v3User.CreatedAt,
					NameLastChangedAt: v3User.NameLastChangedAt,
					SkinHash:          v3User.SkinHash,
					CapeHash:          v3User.CapeHash,
					ServerID:          v3User.ServerID,
					FallbackPlayer:    v3User.FallbackPlayer,
					Clients:           clients,
					UserUUID:          newUUID,
				}
				user := V4User{
					IsAdmin:           v3User.IsAdmin,
					IsLocked:          v3User.IsLocked,
					UUID:              newUUID,
					Username:          v3User.Username,
					PasswordSalt:      v3User.PasswordSalt,
					PasswordHash:      v3User.PasswordHash,
					BrowserToken:      v3User.BrowserToken,
					MinecraftToken:    minecraftPassword,
					APIToken:          v3User.APIToken,
					PreferredLanguage: v3User.PreferredLanguage,
					Players:           []V4Player{player},
					MaxPlayerCount:    Constants.MaxPlayerCountUseDefault,
				}
				users = append(users, user)
			}
			if len(users) > 0 {
				if err := tx.Session(&gorm.Session{FullSaveAssociations: true}).Save(&users).Error; err != nil {
					return err
				}
			}
			userVersion += 1
		}
		if userVersion == 4 && targetUserVersion >= 5 {
			// Version 4 to 5
			// Add LastUsedAt column to Clients, arbitrarily select clients to delete over the maximum count
			if err := tx.AutoMigrate(&V5User{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V5Player{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V5Client{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V5UserOIDCIdentity{}); err != nil {
				return err
			}

			var users []V4User
			if err := (tx.Model(&User{}).FindInBatches(&users, 256, func(txBatch *gorm.DB, batch int) error {
				for _, user := range users {
					if err := txBatch.Exec(`
						UPDATE clients SET last_used_at = CURRENT_TIMESTAMP WHERE last_used_at IS NULL;
						DELETE FROM clients
						WHERE user_uuid = ?
						AND uuid NOT IN (
							SELECT uuid
							FROM clients
							WHERE user_uuid = ?
							ORDER BY last_used_at DESC
							LIMIT ?
						);
					`, user.UUID, user.UUID, Constants.MaxClientCount).Error; err != nil {
						fmt.Println("", user.Username)
						return err
					}
				}
				return nil
			})).Error; err != nil {
				return err
			}

			err := tx.Exec(`
				DROP TRIGGER IF EXISTS v4_insert_unique_username;
				DROP TRIGGER IF EXISTS v4_update_unique_username;
				DROP TRIGGER IF EXISTS v4_insert_unique_player_name;
				DROP TRIGGER IF EXISTS v4_update_unique_player_name;
				DROP TRIGGER IF EXISTS v4_insert_unique_user_oidc_identities;
				DROP TRIGGER IF EXISTS v4_update_unique_user_oidc_identities;
			`).Error
			if err != nil {
				return err
			}

			userVersion += 1
		}
		if userVersion == 5 && targetUserVersion >= 6 {
			// Version 5 to 6

			// Add authMethod to Client table
			if err := tx.AutoMigrate(&V6Client{}); err != nil {
				return err
			}
			if err := tx.Exec("UPDATE clients SET auth_method = ?", AuthMethodUnknown).Error; err != nil {
				return err
			}

			// Switch from BLAKE3 to SHA256 for textures hashes
			log.Printf("Renaming texture files from their BLAKE3 hashes to their SHA256 hashes")

			skinDir := filepath.Join(config.StateDirectory, "skin")
			capeDir := filepath.Join(config.StateDirectory, "cape")

			linkTexture := func(dir string, b3sum string) (string, error) {
				// Get the SHA256 checksum
				b3Path := filepath.Join(dir, fmt.Sprintf("%s.png", b3sum))
				b3File, err := os.Open(b3Path)
				if err != nil {
					return "", err
				}
				defer b3File.Close()
				sha256Hash := sha256.New()
				if _, err := io.Copy(sha256Hash, b3File); err != nil {
					return "", err
				}
				sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))
				sha256Path := filepath.Join(dir, fmt.Sprintf("%s.png", sha256Sum))

				if err := os.Link(b3Path, sha256Path); err == nil {
					log.Printf("Created hardlink to %s from %s", b3Path, sha256Path)
				} else {
					// Fall back to copy when hardlink fails
					sha256File, err := os.Create(sha256Path)
					if err != nil {
						return "", err
					}
					defer sha256File.Close()

					if _, err := b3File.Seek(0, 0); err != nil {
						return "", err
					}
					if _, err := io.Copy(sha256File, b3File); err != nil {
						return "", err
					}
					log.Printf("Copied %s to %s", b3Path, sha256Path)
				}

				unusedTexturePaths = append(unusedTexturePaths, b3Path)

				return sha256Sum, nil
			}

			var players []V6Player
			if err := (tx.Model(&Player{}).FindInBatches(&players, 256, func(txBatch *gorm.DB, batch int) error {
				for i, player := range players {
					// Create hardlinks to the BLAKE3-named texture files with SHA256 names.
					if skinHash, ok := NullStringToOption(&player.SkinHash).Get(); ok {
						skinSha256Sum, err := linkTexture(skinDir, skinHash)
						if err != nil {
							return err
						}
						players[i].SkinHash = MakeNullString(&skinSha256Sum)
					}
					if capeHash, ok := NullStringToOption(&player.CapeHash).Get(); ok {
						capeSha256Sum, err := linkTexture(capeDir, capeHash)
						if err != nil {
							return err
						}
						players[i].CapeHash = MakeNullString(&capeSha256Sum)
					}
				}
				if err := tx.Save(&players).Error; err != nil {
					return err
				}
				return nil
			})).Error; err != nil {
				return fmt.Errorf("failed to migrate texture from BLAKE3 filename to SHA256 filename: %s", err)
			}

			if err := tx.Exec(`
				DROP TRIGGER IF EXISTS v5_insert_unique_username;
				DROP TRIGGER IF EXISTS v5_update_unique_username;
				DROP TRIGGER IF EXISTS v5_insert_unique_player_name;
				DROP TRIGGER IF EXISTS v5_update_unique_player_name;
				DROP TRIGGER IF EXISTS v5_insert_unique_user_oidc_identities;
				DROP TRIGGER IF EXISTS v5_update_unique_user_oidc_identities;
				DROP TRIGGER IF EXISTS v5_insert_clients_max_count;
			`).Error; err != nil {
				return err
			}
			userVersion += 1
		}
		if userVersion == 6 && targetUserVersion >= 7 {
			// Version 6 to 7
			// Rename the account lock to reflect that it disables all login,
			// then add the administrator-controlled chat preference.
			if err := tx.Migrator().RenameColumn(&V6User{}, "is_locked", "is_disabled"); err != nil {
				return err
			}
			if err := tx.Migrator().AddColumn(&User{}, "ChatMode"); err != nil {
				return err
			}
			if err := tx.Model(&User{}).Where("chat_mode IS NULL OR chat_mode = ''").Update("chat_mode", ChatModeEnabled).Error; err != nil {
				return err
			}
			userVersion += 1
		}

		// Migrate one model at a time to preserve the existing order.
		for _, model := range []any{
			&User{}, &Player{}, &Client{}, &Invite{}, &UserOIDCIdentity{},
			&Ban{}, &PlayerCertificate{}, &Report{},
		} {
			if err := tx.AutoMigrate(model); err != nil {
				return err
			}
		}

		err := tx.Exec(fmt.Sprintf(`
			DROP TRIGGER IF EXISTS v6_insert_unique_username;
			DROP TRIGGER IF EXISTS v6_update_unique_username;
			DROP TRIGGER IF EXISTS v6_insert_unique_player_name;
			DROP TRIGGER IF EXISTS v6_update_unique_player_name;
			DROP TRIGGER IF EXISTS v6_insert_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v6_update_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v6_insert_clients_max_count;
			DROP TRIGGER IF EXISTS v7_insert_unique_username;
			DROP TRIGGER IF EXISTS v7_update_unique_username;
			DROP TRIGGER IF EXISTS v7_insert_unique_player_name;
			DROP TRIGGER IF EXISTS v7_update_unique_player_name;
			DROP TRIGGER IF EXISTS v7_insert_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v7_update_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v7_insert_clients_max_count;

			CREATE TRIGGER v%[4]d_insert_unique_username
			BEFORE INSERT ON users
			FOR EACH ROW
			BEGIN
				-- We have to reimplement the regular "UNIQUE constraint
				-- failed" errors here too since we want them to take priority
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: users.username')
				WHERE EXISTS(
					SELECT 1 FROM users WHERE username = NEW.username AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, '%[1]s')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.username AND user_uuid != NEW.uuid
				);
			END;

			CREATE TRIGGER v%[4]d_update_unique_username
			BEFORE UPDATE ON users
			FOR EACH ROW
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: users.username')
				WHERE EXISTS(
					SELECT 1 FROM users WHERE username = NEW.username AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, '%[1]s')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.username AND user_uuid != NEW.uuid
				);
			END;

			CREATE TRIGGER v%[4]d_insert_unique_player_name
			BEFORE INSERT ON players
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: players.name')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.name AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, '%[2]s')
				WHERE EXISTS(
					SELECT 1 from users WHERE username == NEW.name AND uuid != NEW.user_uuid
				);
			END;

			CREATE TRIGGER v%[4]d_update_unique_player_name
			BEFORE UPDATE ON players
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: players.name')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.name AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, '%[2]s')
				WHERE EXISTS(
					SELECT 1 from users WHERE username == NEW.name AND uuid != NEW.user_uuid
				);
			END;

			CREATE TRIGGER v%[4]d_insert_unique_user_oidc_identities
			BEFORE INSERT ON user_oidc_identities
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer, user_oidc_identities.subject')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND issuer == NEW.issuer AND subject == NEW.subject
				);

				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND user_uuid == NEW.user_uuid AND issuer == NEW.issuer
				);
			END;

			CREATE TRIGGER v%[4]d_update_unique_user_oidc_identities
			BEFORE UPDATE ON user_oidc_identities
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer, user_oidc_identities.subject')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND issuer == NEW.issuer AND subject == NEW.subject
				);

				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND user_uuid == NEW.user_uuid AND issuer == NEW.issuer
				);
			END;

			CREATE TRIGGER v%[4]d_insert_clients_max_count
			AFTER INSERT ON clients
			BEGIN
				DELETE FROM clients
				WHERE user_uuid = NEW.user_uuid
				AND uuid NOT IN (
					SELECT uuid
					FROM clients
					WHERE user_uuid = NEW.user_uuid
					ORDER BY last_used_at DESC
					LIMIT %[3]d
				);
			END;
		`, USERNAME_TAKEN_BY_PLAYER_NAME_ERROR, PLAYER_NAME_TAKEN_BY_USERNAME_ERROR, Constants.MaxClientCount, userVersion)).Error
		if err != nil {
			return err
		}

		if err := setUserVersion(tx, userVersion); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Remove old BLAKE3 textures
	for _, unusedTexturePath := range unusedTexturePaths {
		if err := os.Remove(unusedTexturePath); err == nil {
			log.Printf("Removed unused texture file %s", unusedTexturePath)
		} else {
			return fmt.Errorf("failed to remove unused texture file %s: %s", unusedTexturePath, err)
		}
	}

	if initialUserVersion < targetUserVersion {
		log.Printf("Finished migration from version %d to %d", initialUserVersion, userVersion)
	}

	return nil
}
