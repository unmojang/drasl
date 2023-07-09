package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
	"lukechampine.com/blake3"
	"strings"
	"time"
)

const (
	SkinModelSlim    string = "slim"
	SkinModelClassic string = "classic"
)

const (
	SkinVariantSlim    string = "SLIM"
	SkinVariantClassic string = "CLASSIC"
)

func SkinModelToVariant(model string) string {
	switch model {
	case SkinModelSlim:
		return SkinVariantSlim
	case SkinModelClassic:
		return SkinVariantClassic
	default:
		return SkinVariantClassic
	}
}

func MakeNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{Valid: false}
	}
	new_string := *s
	return sql.NullString{
		String: new_string,
		Valid:  true,
	}
}

func UnmakeNullString(ns *sql.NullString) *string {
	if ns.Valid {
		new_string := ns.String
		return &new_string
	}
	return nil
}

func IsValidSkinModel(model string) bool {
	switch model {
	case SkinModelSlim, SkinModelClassic:
		return true
	default:
		return false
	}
}

func UUIDToID(uuid string) (string, error) {
	if len(uuid) != 36 {
		return "", errors.New("Invalid UUID")
	}
	return strings.ReplaceAll(uuid, "-", ""), nil
}

func IDToUUID(id string) (string, error) {
	if len(id) != 32 {
		return "", errors.New("Invalid ID")
	}
	return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:], nil
}

func ValidatePlayerName(app *App, playerName string) error {
	if AnonymousLoginEligible(app, playerName) {
		return errors.New("name is reserved for anonymous login")
	}
	maxLength := app.Constants.MaxPlayerNameLength
	if playerName == "" {
		return errors.New("can't be blank")
	}
	if len(playerName) > maxLength {
		return fmt.Errorf("can't be longer than %d characters", maxLength)
	}
	return nil
}

func ValidateUsername(app *App, username string) error {
	return ValidatePlayerName(app, username)
}

func ValidatePlayerNameOrUUID(app *App, player string) error {
	err := ValidatePlayerName(app, player)
	if err != nil {
		_, err = uuid.Parse(player)
		if err != nil {
			return errors.New("not a valid player name or UUID")
		}
		return err
	}
	return nil
}

func MakeAnonymousUser(app *App, playerName string) (User, error) {
	// TODO think of a better way to do this...
	preimage := bytes.Join([][]byte{
		[]byte("uuid"),
		[]byte(playerName),
		app.KeyB3Sum512,
	}, []byte{})
	sum := blake3.Sum512(preimage)
	accountUUID, err := uuid.FromBytes(sum[:16])
	if err != nil {
		return User{}, err
	}

	user := User{
		UUID:              accountUUID.String(),
		Username:          playerName,
		FallbackPlayer:    playerName,
		PasswordSalt:      []byte{},
		PasswordHash:      []byte{},
		TokenPairs:        []TokenPair{},
		PlayerName:        playerName,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		SkinModel:         SkinModelClassic,
		BrowserToken:      MakeNullString(nil),
		CreatedAt:         time.Now(),
		NameLastChangedAt: time.Now(),
	}
	return user, nil
}

func AnonymousLoginEligible(app *App, playerName string) bool {
	return app.Config.AnonymousLogin.Allow &&
		app.AnonymousLoginUsernameRegex.MatchString(playerName) &&
		len(playerName) <= app.Constants.MaxPlayerNameLength
}

func ValidatePassword(app *App, password string) error {
	if password == "" {
		return errors.New("can't be blank")
	}
	if len(password) < app.Config.MinPasswordLength {
		message := fmt.Sprintf("password must be longer than %d characters", app.Config.MinPasswordLength)
		return errors.New(message)
	}
	return nil
}

func IsValidPreferredLanguage(preferredLanguage string) bool {
	switch preferredLanguage {
	case "sq",
		"ar",
		"be",
		"bg",
		"ca",
		"zh",
		"hr",
		"cs",
		"da",
		"nl",
		"en",
		"et",
		"fi",
		"fr",
		"de",
		"el",
		"iw",
		"hi",
		"hu",
		"is",
		"in",
		"ga",
		"it",
		"ja",
		"ko",
		"lv",
		"lt",
		"mk",
		"ms",
		"mt",
		"no",
		"nb",
		"nn",
		"pl",
		"pt",
		"ro",
		"ru",
		"sr",
		"sk",
		"sl",
		"es",
		"sv",
		"th",
		"tr",
		"uk",
		"vi":
		return true
	default:
		return false
	}
}

const SCRYPT_N = 32768
const SCRYPT_r = 8
const SCRYPT_p = 1
const SCRYPT_BYTES = 32

func HashPassword(password string, salt []byte) ([]byte, error) {
	return scrypt.Key(
		[]byte(password),
		salt,
		SCRYPT_N,
		SCRYPT_r,
		SCRYPT_p,
		SCRYPT_BYTES,
	)
}

func SkinURL(app *App, hash string) string {
	return app.FrontEndURL + "/drasl/texture/skin/" + hash + ".png"
}

func InviteURL(app *App, invite *Invite) string {
	return app.FrontEndURL + "/drasl/registration?invite=" + invite.Code
}

func UserSkinURL(app *App, user *User) *string {
	if !user.SkinHash.Valid {
		return nil
	}
	url := SkinURL(app, user.SkinHash.String)
	return &url
}

func CapeURL(app *App, hash string) string {
	return app.FrontEndURL + "/drasl/texture/cape/" + hash + ".png"
}

type TokenPair struct {
	ClientToken string `gorm:"primaryKey"`
	AccessToken string `gorm:"index"`
	Valid       bool   `gorm:"not null"`
	UserUUID    string
	User        User
}

type User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string      `gorm:"primaryKey"`
	Username          string      `gorm:"unique;not null"`
	PasswordSalt      []byte      `gorm:"not null"`
	PasswordHash      []byte      `gorm:"not null"`
	TokenPairs        []TokenPair `gorm:"foreignKey:UserUUID"`
	ServerID          sql.NullString
	PlayerName        string `gorm:"unique"`
	FallbackPlayer    string
	PreferredLanguage string
	BrowserToken      sql.NullString `gorm:"index"`
	SkinHash          sql.NullString `gorm:"index"`
	SkinModel         string
	CapeHash          sql.NullString `gorm:"index"`
	CreatedAt         time.Time
	NameLastChangedAt time.Time
}

type Invite struct {
	Code      string `gorm:"primaryKey"`
	CreatedAt time.Time
}
