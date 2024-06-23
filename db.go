package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"path"
)

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

const CURRENT_USER_VERSION = 3

func setUserVersion(tx *gorm.DB, userVersion uint) error {
	return tx.Exec(fmt.Sprintf("PRAGMA user_version = %d;", userVersion)).Error
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

	err := db.Transaction(func(tx *gorm.DB) error {
		if userVersion < CURRENT_USER_VERSION {
			log.Printf("Started migration of database version %d to version %d", userVersion, CURRENT_USER_VERSION)
		}
		if userVersion == 0 {
			// Version 0 to 1
			// Add OfflineUUID column
			if err := tx.Migrator().AddColumn(&User{}, "offline_uuid"); err != nil {
				return err
			}
			var users []User
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
			if err := tx.Migrator().AddColumn(&Client{}, "client_token"); err != nil {
				return err
			}
			if err := tx.Exec("UPDATE clients SET client_token = uuid").Error; err != nil {
				return err
			}
			userVersion += 1
		}
		if userVersion == 2 {
			// Version 2 to 3
			// Add APIToken
			if err := tx.Migrator().AddColumn(&User{}, "api_token"); err != nil {
				return err
			}
			var users []User
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

		err := tx.AutoMigrate(&User{})
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

		if err := setUserVersion(tx, userVersion); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}
