package main

import (
	"crypto/md5"
	"database/sql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/samber/mo"
	"golang.org/x/crypto/scrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

const (
	SkinModelSlim    string = "slim"
	SkinModelClassic string = "classic"
)

const (
	TextureTypeSkin string = "skin"
	TextureTypeCape string = "cape"
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

func NullStringToOption(ns *sql.NullString) mo.Option[string] {
	if ns.Valid {
		return mo.Some(ns.String)
	}
	return mo.None[string]()
}

func OptionToNullString(option mo.Option[string]) sql.NullString {
	if s, ok := option.Get(); ok {
		return sql.NullString{
			String: s,
			Valid:  true,
		}
	}
	return sql.NullString{Valid: false}
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
		return "", &UserError{Message: "invalid UUID"}
	}
	return strings.ReplaceAll(uuid, "-", ""), nil
}

func IDToUUID(id string) (string, error) {
	if len(id) != 32 {
		return "", &UserError{Message: "invalid ID"}
	}
	return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:], nil
}

func ParseUUID(idOrUUID string) (string, error) {
	if len(idOrUUID) == 32 {
		uuid_, err := IDToUUID(idOrUUID)
		if err != nil {
			return "", err
		}
		if _, err := uuid.Parse(uuid_); err != nil {
			return "", err
		}
		return uuid_, nil
	}
	if len(idOrUUID) == 36 {
		if _, err := uuid.Parse(idOrUUID); err != nil {
			return "", err
		}
		return idOrUUID, nil
	}
	return "", &UserError{Message: "invalid ID or UUID"}
}

type Plural struct {
	Message string
	N       int
}

func (app *App) ValidatePlayerName(playerName string) error {
	if app.TransientLoginEligible(playerName) {
		return &UserError{Message: "name is reserved for transient login"}
	}
	maxLength := Constants.MaxPlayerNameLength
	if playerName == "" {
		return &UserError{Message: "can't be blank"}
	}
	if len(playerName) > maxLength {
		return &UserError{
			Message: "can't be longer than %d character",
			Plural: mo.Some(Plural{
				Message: "can't be longer than %d characters",
				N:       maxLength,
			}),
			Params: []interface{}{maxLength},
		}
	}

	if !app.ValidPlayerNameRegex.MatchString(playerName) {
		return &UserError{Message: "must match the following regular expression: %s", Params: []interface{}{app.Config.ValidPlayerNameRegex}}
	}
	return nil
}

func (app *App) ValidateUsername(username string) error {
	// Valid username are either valid player names or valid email addresses
	playerNameErr := app.ValidatePlayerName(username)
	if playerNameErr == nil {
		return nil
	}
	_, emailErr := mail.ParseAddress(username)
	if emailErr == nil {
		return nil
	}
	return &UserError{Message: "neither a valid player name (%s) nor an email address", Params: []interface{}{playerNameErr}}
}

func (app *App) ValidatePlayerNameOrUUID(player string) error {
	err := app.ValidatePlayerName(player)
	if err != nil {
		_, uuidErr := uuid.Parse(player)
		if uuidErr != nil {
			return &UserError{Message: "not a valid player name or UUID"}
		}
		return nil
	}
	return nil
}

func (app *App) ValidateMaxPlayerCount(maxPlayerCount int) error {
	if maxPlayerCount < 0 && maxPlayerCount != app.Constants.MaxPlayerCountUnlimited && maxPlayerCount != app.Constants.MaxPlayerCountUseDefault {
		return &UserError{Message: "must be greater than 0, or use -1 to indicate unlimited players, or use -2 to use the system default"}
	}
	return nil
}

// func MakeTransientUser(app *App, playerName string) (User, error) {
// 	preimage := bytes.Join([][]byte{
// 		[]byte("uuid"),
// 		[]byte(playerName),
// 		app.KeyB3Sum512,
// 	}, []byte{})
// 	sum := blake3.Sum512(preimage)
// 	accountUUID, err := uuid.FromBytes(sum[:16])
// 	if err != nil {
// 		return User{}, err
// 	}
//
// 	apiToken, err := MakeAPIToken()
// 	if err != nil {
// 		return User{}, err
// 	}
//
// 	user := User{
// 		UUID:              accountUUID.String(),
// 		Username:          playerName,
// 		FallbackPlayer:    playerName,
// 		PasswordSalt:      []byte{},
// 		PasswordHash:      []byte{},
// 		Clients:           []Client{},
// 		PlayerName:        playerName,
// 		PreferredLanguage: app.Config.DefaultPreferredLanguage,
// 		SkinModel:         SkinModelClassic,
// 		BrowserToken:      MakeNullString(nil),
// 		APIToken:          apiToken,
// 		CreatedAt:         time.Now(),
// 		NameLastChangedAt: time.Now(),
// 	}
// 	return user, nil
// }

func (app *App) TransientLoginEligible(playerName string) bool {
	return app.Config.TransientUsers.Allow &&
		app.TransientUsernameRegex.MatchString(playerName) &&
		len(playerName) <= Constants.MaxPlayerNameLength
}

func (app *App) ValidatePassword(password string) error {
	if password == "" {
		return &UserError{Message: "can't be blank"}
	}
	if len(password) < app.Config.MinPasswordLength {
		return &UserError{
			Message: "must be longer than %d character",
			Plural: mo.Some(Plural{
				Message: "must be longer than %d characters",
				N:       app.Config.MinPasswordLength,
			}),
			Params: []interface{}{app.Config.MinPasswordLength},
		}
	}
	return nil
}

func OfflineUUID(playerName string) (string, error) {
	str := "OfflinePlayer:" + playerName

	hasher := md5.New()
	hasher.Write([]byte(str))
	md5Bytes := hasher.Sum(nil)

	// https://hg.openjdk.org/jdk8/jdk8/jdk/file/tip/src/share/classes/java/util/UUID.java#l162
	md5Bytes[6] &= 0x0f // clear version
	md5Bytes[6] |= 0x30 // set to version 3
	md5Bytes[8] &= 0x3f // clear variant
	md5Bytes[8] |= 0x80 // set to IETF variant

	offlineUUID, err := uuid.FromBytes(md5Bytes)
	if err != nil {
		return "", err
	}

	return offlineUUID.String(), nil
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

func (app *App) SkinURL(hash string) (string, error) {
	return url.JoinPath(app.FrontEndURL, "web/texture/skin/"+hash+".png")
}

func (app *App) InviteURL(invite *Invite) (string, error) {
	url, err := url.JoinPath(app.FrontEndURL, "web/registration")
	if err != nil {
		return "", err
	}
	return url + "?invite=" + invite.Code, nil
}

func (app *App) CapeURL(hash string) (string, error) {
	return url.JoinPath(app.FrontEndURL, "web/texture/cape/"+hash+".png")
}

func MakeAPIToken() (string, error) {
	return RandomBase62(16)
}

func MakeMinecraftToken() (string, error) {
	random, err := RandomBase62(16)
	if err != nil {
		return "", err
	}
	return "MC_" + random, nil
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
				Subject:   client.UUID,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				Audience:  nil,
				Issuer:    "drasl",
			},
			Version: client.Version,
			StaleAt: jwt.NewNumericDate(staleAt),
		})
	return token.SignedString(app.PrivateKey)
}

type StaleTokenPolicy int

const (
	StalePolicyAllow StaleTokenPolicy = iota
	StalePolicyDeny
)

func (app *App) GetClient(accessToken string, stalePolicy StaleTokenPolicy) *Client {
	token, err := jwt.ParseWithClaims(accessToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return app.PrivateKey.Public(), nil
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
	result := app.DB.Preload("User").Preload("Player").First(&client, "uuid = ?", claims.RegisteredClaims.Subject)
	if result.Error != nil {
		return nil
	}
	if stalePolicy == StalePolicyDeny && time.Now().After(claims.StaleAt.Time) {
		return nil
	}
	if claims.Subject != client.UUID || claims.Version != client.Version {
		return nil
	}
	return &client
}

func (app *App) GetMaxPlayerCount(user *User) int {
	if user.IsAdmin {
		return Constants.MaxPlayerCountUnlimited
	}
	if user.MaxPlayerCount == Constants.MaxPlayerCountUseDefault {
		return app.Config.DefaultMaxPlayerCount
	}
	return user.MaxPlayerCount
}

type User struct {
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
	Players           []Player
	MaxPlayerCount    int
	Clients           []Client
	OIDCIdentities    []UserOIDCIdentity
}

func (user *User) BeforeDelete(tx *gorm.DB) error {
	if err := tx.Clauses(clause.Returning{}).Where("user_uuid = ?", user.UUID).Delete(&Player{}).Error; err != nil {
		return err
	}
	if err := tx.Clauses(clause.Returning{}).Where("user_uuid = ?", user.UUID).Delete(&Client{}).Error; err != nil {
		return err
	}
	if err := tx.Clauses(clause.Returning{}).Where("user_uuid = ?", user.UUID).Delete(&UserOIDCIdentity{}).Error; err != nil {
		return err
	}
	return nil
}

type UserOIDCIdentity struct {
	ID       uint `gorm:"primaryKey"`
	User     User
	UserUUID string `gorm:"index;not null"`
	Subject  string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
	Issuer   string `gorm:"uniqueIndex:subject_issuer_unique_index;not null"`
}

func (UserOIDCIdentity) TableName() string {
	return "user_oidc_identities"
}

func (player *Player) AfterFind(tx *gorm.DB) error {
	if err := tx.Find(&player.Clients, "player_uuid = ?", player.UUID).Error; err != nil {
		return err
	}
	return nil
}

func (user *User) AfterFind(tx *gorm.DB) error {
	if err := tx.Find(&user.OIDCIdentities, "user_uuid = ?", user.UUID).Error; err != nil {
		return err
	}
	if err := tx.Find(&user.Players, "user_uuid = ?", user.UUID).Error; err != nil {
		return err
	}
	if err := tx.Find(&user.Clients, "user_uuid = ?", user.UUID).Error; err != nil {
		return err
	}
	return nil
}

type Player struct {
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
	User              User
	UserUUID          string   `gorm:"not null"`
	Clients           []Client `gorm:"constraint:OnDelete:CASCADE"`
}

func (player *Player) BeforeDelete(tx *gorm.DB) error {
	return tx.Clauses(clause.Returning{}).Where("player_uuid = ?", player.UUID).Delete(&Client{}).Error
}

type Client struct {
	UUID        string `gorm:"primaryKey"`
	ClientToken string
	Version     int
	UserUUID    string `gorm:"not null"`
	User        User
	PlayerUUID  sql.NullString `gorm:"index"`
	Player      *Player
}

func (app *App) GetSkinURL(player *Player) (*string, error) {
	if !player.SkinHash.Valid {
		return nil, nil
	}
	url, err := app.SkinURL(player.SkinHash.String)
	if err != nil {
		return nil, err
	}
	return &url, nil
}

func (app *App) GetCapeURL(player *Player) (*string, error) {
	if !player.CapeHash.Valid {
		return nil, nil
	}
	url, err := app.CapeURL(player.CapeHash.String)
	if err != nil {
		return nil, err
	}
	return &url, nil
}

type Invite struct {
	Code      string `gorm:"primaryKey"`
	CreatedAt time.Time
}
