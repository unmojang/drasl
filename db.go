package main

import (
	"database/sql"
	"errors"
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"path"
	"time"
)

const CURRENT_USER_VERSION = 4

const PLAYER_NAME_TAKEN_BY_USERNAME_ERROR = "PLAYER_NAME_TAKEN_BY_USERNAME"
const USERNAME_TAKEN_BY_PLAYER_NAME_ERROR = "USERNAME_TAKEN_BY_PLAYER_NAME"

type Error error

func IsErrorUniqueFailed(err error) bool {
	if err == nil {
		return false
	}
	// Work around https://stackoverflow.com/questions/75489773/why-do-i-get-second-argument-to-errors-as-should-not-be-error-build-error-in
	e := (errors.New("UNIQUE constraint failed")).(Error)
	return errors.As(err, &e) || IsErrorPlayerNameTakenByUsername(err) || IsErrorUsernameTakenByPlayerName(err)
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

type V1User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string     `gorm:"primaryKey"`
	Username          string     `gorm:"unique;not null"`
	PasswordSalt      []byte     `gorm:"not null"`
	PasswordHash      []byte     `gorm:"not null"`
	Clients           []V3Client `gorm:"foreignKey:UserUUID"`
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

type V2Client struct {
	ClientToken string `gorm:"primaryKey"`
	Version     int
	UserUUID    string
	User        V3User
}

func (V2Client) TableName() string {
	return "clients"
}

type V3Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string
	User        V3User
}

func (V3Client) TableName() string {
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

type V4User = User
type V4Player = Player
type V4Client = Client

func OpenDB(config *Config) (*gorm.DB, error) {
	dbPath := path.Join(config.StateDirectory, "drasl.db")
	_, err := os.Stat(dbPath)
	alreadyExisted := err == nil

	db := Unwrap(gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}))
	err = migrate(db, alreadyExisted)
	if err != nil {
		return nil, fmt.Errorf("Error migrating database: %w", err)
	}

	return db, nil
}

func setUserVersion(tx *gorm.DB, userVersion uint) error {
	// PRAGMA user_version = ? doesn't work here
	return tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", userVersion)).Error
}

func migrate(db *gorm.DB, alreadyExisted bool) error {
	var userVersion uint

	if alreadyExisted {
		if err := db.Raw("PRAGMA user_version;").Scan(&userVersion).Error; err != nil {
			return nil
		}
	} else {
		userVersion = CURRENT_USER_VERSION
	}

	initialUserVersion := userVersion
	if initialUserVersion < CURRENT_USER_VERSION {
		log.Printf("Started migration of database version %d to %d", userVersion, CURRENT_USER_VERSION)
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if userVersion == 0 {
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
		if userVersion == 1 {
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
		if userVersion == 2 {
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
		if userVersion == 3 {
			// Version 3 to 4
			// Split Users and Players

			var v3Users []V3User
			if err := tx.Preload("Clients").Find(&v3Users).Error; err != nil {
				return err
			}

			if err := tx.AutoMigrate(&V4User{}); err != nil {
				return err
			}
			if err := tx.AutoMigrate(&V4Client{}); err != nil {
				return err
			}

			// Drop player_name, it has a non-null constraint and SQLite has no
			// mechanism to remove it
			if err := tx.Migrator().DropColumn(&V4User{}, "player_name"); err != nil {
				return err
			}

			users := make([]V4User, 0, len(v3Users))
			for _, v3User := range v3Users {
				clients := make([]V4Client, 0, len(v3User.Clients))
				for _, v3Client := range v3User.Clients {
					clients = append(clients, V4Client{
						UUID:        v3Client.UUID,
						ClientToken: v3Client.ClientToken,
						Version:     v3Client.Version,
						PlayerUUID:  v3Client.UserUUID,
					})
				}
				player := V4Player{
					UUID:              v3User.UUID,
					Name:              v3User.PlayerName,
					OfflineUUID:       v3User.OfflineUUID,
					CreatedAt:         v3User.CreatedAt,
					NameLastChangedAt: v3User.NameLastChangedAt,
					SkinHash:          v3User.SkinHash,
					CapeHash:          v3User.CapeHash,
					ServerID:          v3User.ServerID,
					FallbackPlayer:    v3User.FallbackPlayer,
					Clients:           clients,
					UserUUID:          v3User.UUID,
				}
				user := V4User{
					IsAdmin:           v3User.IsAdmin,
					IsLocked:          v3User.IsLocked,
					UUID:              v3User.UUID,
					Username:          v3User.Username,
					PasswordSalt:      v3User.PasswordSalt,
					PasswordHash:      v3User.PasswordHash,
					BrowserToken:      v3User.BrowserToken,
					APIToken:          v3User.APIToken,
					PreferredLanguage: v3User.PreferredLanguage,
					Players:           []Player{player},
					MaxPlayerCount:    Constants.MaxPlayerCountUseDefault,
				}
				user.Players = append(user.Players, player)
				users = append(users, user)
			}
			if err := tx.Session(&gorm.Session{FullSaveAssociations: true}).Save(&users).Error; err != nil {
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

		err = tx.Exec(fmt.Sprintf(`
			DROP TRIGGER IF EXISTS v4_insert_unique_username;
			CREATE TRIGGER v4_insert_unique_username
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

			DROP TRIGGER IF EXISTS v4_update_unique_username;
			CREATE TRIGGER v4_update_unique_username
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

			DROP TRIGGER IF EXISTS v4_insert_unique_player_name;
			CREATE TRIGGER v4_insert_unique_player_name
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

			DROP TRIGGER IF EXISTS v4_update_unique_player_name;
			CREATE TRIGGER v4_update_unique_player_name
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
		`, USERNAME_TAKEN_BY_PLAYER_NAME_ERROR, PLAYER_NAME_TAKEN_BY_USERNAME_ERROR)).Error
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

	if initialUserVersion < CURRENT_USER_VERSION {
		log.Printf("Finished migration from version %d to %d", initialUserVersion, userVersion)
	}

	return nil
}
