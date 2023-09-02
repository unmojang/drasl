package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
	"lukechampine.com/blake3"
	"net/url"
	"strings"
	"time"
)

const (
	SkinModelSlim    string = "slim"
	SkinModelClassic string = "classic"
)

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
	if TransientLoginEligible(app, playerName) {
		return errors.New("name is reserved for transient login")
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

func MakeTransientUser(app *App, playerName string) (User, error) {
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
		Clients:           []Client{},
		PlayerName:        playerName,
		PreferredLanguage: app.Config.DefaultPreferredLanguage,
		SkinModel:         SkinModelClassic,
		BrowserToken:      MakeNullString(nil),
		CreatedAt:         time.Now(),
		NameLastChangedAt: time.Now(),
	}
	return user, nil
}

func TransientLoginEligible(app *App, playerName string) bool {
	return app.Config.TransientUsers.Allow &&
		app.TransientUsernameRegex.MatchString(playerName) &&
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

func SkinURL(app *App, hash string) (string, error) {
	return url.JoinPath(app.FrontEndURL, "drasl/texture/skin/"+hash+".png")
}

func InviteURL(app *App, invite *Invite) (string, error) {
	url, err := url.JoinPath(app.FrontEndURL, "drasl/registration")
	if err != nil {
		return "", err
	}
	return url + "?invite=" + invite.Code, nil
}

func UserSkinURL(app *App, user *User) (*string, error) {
	if !user.SkinHash.Valid {
		return nil, nil
	}
	url, err := SkinURL(app, user.SkinHash.String)
	if err != nil {
		return nil, err
	}
	return &url, nil
}

func CapeURL(app *App, hash string) (string, error) {
	return url.JoinPath(app.FrontEndURL, "drasl/texture/cape/"+hash+".png")
}

type Client struct {
	ClientToken string `gorm:"primaryKey"`
	Version     int
	UserUUID    string
	User        User
}

type TokenClaims struct {
	jwt.RegisteredClaims
	Version int              `json:"version"`
	StaleAt *jwt.NumericDate `json:"staleAt"`
}

var DISTANT_FUTURE time.Time = Unwrap(time.Parse(time.RFC3339Nano, "2038-01-01T00:00:00.000000000Z"))

func (app *App) MakeAccessToken(client Client) (string, error) {
	var expiresAt time.Time
	if app.Config.TokenExpireSec > 0 {
		expiresAt = time.Now().Add(time.Duration(app.Config.TokenExpireSec) * time.Second)
	} else {
		expiresAt = DISTANT_FUTURE
	}
	var staleAt time.Time
	if app.Config.TokenStaleSec > 0 {
		staleAt = time.Now().Add(time.Duration(app.Config.TokenStaleSec) * time.Second)
	} else {
		staleAt = DISTANT_FUTURE
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512,
		TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   client.ClientToken,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				Audience:  nil,
				Issuer:    "drasl",
			},
			Version: client.Version,
			StaleAt: jwt.NewNumericDate(staleAt),
		})
	return token.SignedString(app.Key)
}

type StaleTokenPolicy int

const (
	StalePolicyAllow StaleTokenPolicy = iota
	StalePolicyDeny
)

func (app *App) GetClient(accessToken string, stalePolicy StaleTokenPolicy) *Client {
	token, err := jwt.ParseWithClaims(accessToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return app.Key.Public(), nil
	})
	if err != nil {
		return nil
	}
	if !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil
	}

	var client Client
	result := app.DB.Preload("User").First(&client, "client_token = ?", claims.RegisteredClaims.Subject)
	if result.Error != nil {
		return nil
	}
	if stalePolicy == StalePolicyDeny && time.Now().After(claims.StaleAt.Time) {
		return nil
	}
	if claims.Subject != client.ClientToken || claims.Version != client.Version {
		return nil
	}
	return &client
}

type User struct {
	IsAdmin           bool
	IsLocked          bool
	UUID              string   `gorm:"primaryKey"`
	Username          string   `gorm:"unique;not null"`
	PasswordSalt      []byte   `gorm:"not null"`
	PasswordHash      []byte   `gorm:"not null"`
	Clients           []Client `gorm:"foreignKey:UserUUID"`
	ServerID          sql.NullString
	PlayerName        string `gorm:"unique;not null;type:text collate nocase"`
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
