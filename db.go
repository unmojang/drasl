package main

import (
	"database/sql"
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/samber/mo"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"
)

const CURRENT_USER_VERSION = 5

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

type V5User = User
type V5Player = Player
type V5Client = Client
type V5UserOIDCIdentity = UserOIDCIdentity

func OpenDB(config *Config) (*gorm.DB, error) {
	dbPath := path.Join(config.StateDirectory, "drasl.db")
	_, err := os.Stat(dbPath)
	alreadyExisted := err == nil

	db := Unwrap(gorm.Open(sqlite.Open(dbPath), &gorm.Config{
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
			if err := tx.Migrator().AddColumn(&V5Client{}, "last_used_at"); err != nil {
				return err
			}
			if err := tx.Exec(fmt.Sprintf(`
				UPDATE clients SET last_used_at = CURRENT_TIMESTAMP WHERE last_used_at IS NULL;
				DELETE FROM clients
				WHERE uuid NOT IN (
					SELECT uuid
					FROM clients
					ORDER BY last_used_at DESC
					LIMIT %d
				);
			`, Constants.MaxClientCount)).Error; err != nil {
				return err
			}
			userVersion += 1
		}

		err := tx.AutoMigrate(&User{})
		if err != nil {
			return err
		}

		err = tx.AutoMigrate(&Player{})
		if err != nil {
			return err
		}

		err = tx.AutoMigrate(&Client{})
		if err != nil {
			return err
		}

		err = tx.AutoMigrate(&Invite{})
		if err != nil {
			return err
		}

		err = tx.AutoMigrate(&UserOIDCIdentity{})
		if err != nil {
			return err
		}

		err = tx.Exec(fmt.Sprintf(`
			DROP TRIGGER IF EXISTS v4_insert_unique_username;
			DROP TRIGGER IF EXISTS v4_update_unique_username;
			DROP TRIGGER IF EXISTS v4_insert_unique_player_name;
			DROP TRIGGER IF EXISTS v4_update_unique_player_name;
			DROP TRIGGER IF EXISTS v4_insert_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v4_update_unique_user_oidc_identities;

			DROP TRIGGER IF EXISTS v5_insert_unique_username;
			DROP TRIGGER IF EXISTS v5_update_unique_username;
			DROP TRIGGER IF EXISTS v5_insert_unique_player_name;
			DROP TRIGGER IF EXISTS v5_update_unique_player_name;
			DROP TRIGGER IF EXISTS v5_insert_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v5_update_unique_user_oidc_identities;
			DROP TRIGGER IF EXISTS v5_insert_clients_max_count;

			CREATE TRIGGER v5_insert_unique_username
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

			CREATE TRIGGER v5_update_unique_username
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

			CREATE TRIGGER v5_insert_unique_player_name
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

			CREATE TRIGGER v5_update_unique_player_name
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

			CREATE TRIGGER v5_insert_unique_user_oidc_identities
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

			CREATE TRIGGER v5_update_unique_user_oidc_identities
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

			CREATE TRIGGER v5_insert_clients_max_count
			AFTER INSERT ON clients
			BEGIN
				DELETE FROM clients
				WHERE uuid NOT IN (
					SELECT uuid
					FROM clients
					ORDER BY last_used_at DESC
					LIMIT %[3]d
				);
			END;
		`, USERNAME_TAKEN_BY_PLAYER_NAME_ERROR, PLAYER_NAME_TAKEN_BY_USERNAME_ERROR, Constants.MaxClientCount)).Error
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

	if initialUserVersion < targetUserVersion {
		log.Printf("Finished migration from version %d to %d", initialUserVersion, userVersion)
	}

	return nil
}
