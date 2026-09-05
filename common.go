package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dgraph-io/ristretto"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/leonelquinteros/gotext"
	"github.com/samber/mo"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const MAX_PLAYER_NAMES_TO_IDS = 10
const MAX_PLAYER_NAMES_TO_IDS_INTERVAL = 1 * time.Second

const CONTEXT_KEY_REQ = "DraslReq"
const CONTEXT_KEY_LOCALE = "DraslLocale"
const CONTEXT_KEY_USER = "DraslUser"
const CONTEXT_KEY_PLAYER = "DraslPlayer"
const CONTEXT_KEY_MAYBE_PLAYER = "DraslMaybePlayer"
const CONTEXT_KEY_CLIENT = "DraslClient"
const CONTEXT_KEY_MAYBE_USER = "DraslMaybeUser"
const CONTEXT_KEY_NONCE = "DraslNonce"

func (app *App) AEADEncrypt(plaintext []byte) ([]byte, error) {
	nonceSize := app.AEAD.NonceSize()

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := app.AEAD.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (app *App) AEADDecrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := app.AEAD.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[0:nonceSize]
	message := ciphertext[nonceSize:]
	return app.AEAD.Open(nil, nonce, message, nil)
}

func (app *App) EncryptCookieValue(plaintext string) (string, error) {
	ciphertext, err := app.AEADEncrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (app *App) DecryptCookieValue(armored string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(armored)
	if err != nil {
		return nil, err
	}
	return app.AEADDecrypt(ciphertext)
}

type OIDCProvider struct {
	Config       RegistrationOIDCConfig
	RelyingParty rp.RelyingParty
}

// OIDCData is the serialized payload of the OIDC data cookie. It carries
// the ID token, the UserInfo claims fetched from the UserInfo endpoint, and the
// nonce that was sent in the authorization request (so the ID token can be
// re-validated against it on subsequent requests).
type OIDCData struct {
	IDToken  string         `json:"idToken"`
	UserInfo *oidc.UserInfo `json:"userInfo"`
	Nonce    string         `json:"nonce"`
}

type Translatable struct {
	MsgID       string
	MsgIDPlural mo.Option[string]
	N           mo.Option[int]
	Params      []any
}

func Tr(msgid string, params ...any) Translatable {
	return Translatable{
		MsgID:  msgid,
		Params: params,
	}
}

func TrN(singular, plural string, n int, params ...any) Translatable {
	return Translatable{
		MsgID:       singular,
		MsgIDPlural: mo.Some(plural),
		N:           mo.Some(n),
		Params:      params,
	}
}

func (t Translatable) Translate(l *gotext.Locale) string {
	translatedParams := make([]any, 0, len(t.Params))
	for _, param := range t.Params {
		switch v := param.(type) {
		case *UserError:
			translated := v.Translatable.Translate(l)
			translatedParams = append(translatedParams, translated)
		default:
			translatedParams = append(translatedParams, param)
		}
	}

	if plural, ok := t.MsgIDPlural.Get(); ok {
		return l.GetN(t.MsgID, plural, t.N.OrElse(1), translatedParams...)
	}
	return l.Get(t.MsgID, translatedParams...)
}

type UserError struct {
	Code         mo.Option[int]
	Translatable Translatable
}

func (e *UserError) Error() string {
	t := e.Translatable
	if plural, ok := t.MsgIDPlural.Get(); ok && t.N.OrElse(1) > 1 {
		return fmt.Sprintf(plural, t.Params...)
	}
	return fmt.Sprintf(t.MsgID, t.Params...)
}

func NewUserError(t Translatable) error {
	return &UserError{
		Translatable: t,
	}
}

func NewUserErrorWithCode(code int, t Translatable) error {
	return &UserError{
		Code:         mo.Some(code),
		Translatable: t,
	}
}

func NewBadRequestUserError(t Translatable) error {
	return &UserError{
		Code:         mo.Some(http.StatusBadRequest),
		Translatable: t,
	}
}

var InternalServerError error = &UserError{
	Code:         mo.Some(http.StatusInternalServerError),
	Translatable: Tr("Internal server error"),
}

type StatusError struct {
	UserError
}

func (e *StatusError) StatusCode() int {
	return e.Code.OrElse(http.StatusInternalServerError)
}

func httpStatusTranslatable(code int) Translatable {
	switch code {
	case http.StatusBadRequest:
		return Tr("Bad Request")
	case http.StatusUnauthorized:
		return Tr("Unauthorized")
	case http.StatusForbidden:
		return Tr("Forbidden")
	case http.StatusNotFound:
		return Tr("Not Found")
	case http.StatusMethodNotAllowed:
		return Tr("Method Not Allowed")
	case http.StatusRequestTimeout:
		return Tr("Request Timeout")
	case http.StatusRequestEntityTooLarge:
		return Tr("Request Entity Too Large")
	case http.StatusUnsupportedMediaType:
		return Tr("Unsupported Media Type")
	case http.StatusTooManyRequests:
		return Tr("Too Many Requests")
	case http.StatusInternalServerError:
		return Tr("Internal server error")
	case http.StatusBadGateway:
		return Tr("Bad Gateway")
	case http.StatusServiceUnavailable:
		return Tr("Service Unavailable")
	default:
		return Tr(http.StatusText(code))
	}
}

type ConstantsType struct {
	MaxPlayerCountUseDefault int
	MaxPlayerCountUnlimited  int
	ConfigDirectory          string
	MaxClientCount           int
	Version                  string
	License                  string
	LicenseURL               string
	RepositoryURL            string
	SwaggerUIURL             string
}

var Constants = &ConstantsType{
	MaxPlayerCountUseDefault: -2,
	MaxPlayerCountUnlimited:  -1,
	MaxClientCount:           256,
	ConfigDirectory:          GetDefaultConfigDirectory(),
	Version:                  VERSION,
	License:                  LICENSE,
	LicenseURL:               LICENSE_URL,
	RepositoryURL:            REPOSITORY_URL,
	SwaggerUIURL:             SWAGGER_UI_URL,
}

func MakeRequestCacheKey(url string, method string, body []byte) []byte {
	return bytes.Join(
		[][]byte{
			[]byte(url),
			[]byte(method),
			body,
		},
		[]byte{0},
	)
}

type RequestCacheValue struct {
	StatusCode int
	BodyBytes  []byte
}

func (app *App) CachedGet(url string, ttl int) (RequestCacheValue, error) {
	cacheKey := MakeRequestCacheKey(url, "GET", nil)
	if ttl > 0 {
		// If another GET to this URL is already in progress, wait for it to
		// finish and then check the cache.
		unlock := app.GetURLMutex.Lock(url)
		defer unlock()
		cachedResponse, found := app.RequestCache.Get(cacheKey)
		if found {
			return cachedResponse.(RequestCacheValue), nil
		}
	}

	res, err := MakeHTTPClient().Get(url)
	if err != nil {
		return RequestCacheValue{}, err
	}
	defer res.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(res.Body)
	if err != nil {
		return RequestCacheValue{}, err
	}

	response := RequestCacheValue{
		StatusCode: res.StatusCode,
		BodyBytes:  buf.Bytes(),
	}

	// Don't cache HTTP 429 responses
	if ttl > 0 && res.StatusCode != http.StatusTooManyRequests {
		app.RequestCache.SetWithTTL(cacheKey, response, 0, time.Duration(ttl)*time.Second)
		app.RequestCache.Wait()
	}

	return response, nil
}

func (app *App) GetSkinPath(hash string) string {
	dir := path.Join(app.Config.StateDirectory, "skin")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func (app *App) GetCapePath(hash string) string {
	dir := path.Join(app.Config.StateDirectory, "cape")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func (app *App) IsDefaultAdmin(user *User) bool {
	return Contains(app.Config.DefaultAdmins, user.Username)
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Agent struct {
	Name    string `json:"name"`
	Version uint   `json:"version"`
}

type YggdrasilError struct {
	Code         int
	Error_       mo.Option[string]
	ErrorMessage mo.Option[string]
}

func (e *YggdrasilError) Error() string {
	return e.ErrorMessage.OrElse(e.Error_.OrElse("internal server error"))
}

type YggdrasilErrorResponse struct {
	Path         *string `json:"path,omitempty"`
	Error        *string `json:"error,omitempty"`
	ErrorMessage *string `json:"errorMessage,omitempty"`
}

type PathType int

const (
	PathTypeYggdrasil PathType = iota
	PathTypeWeb
	PathTypeAPI
)

func (app *App) GetPathType(baseRelative string) PathType {
	if app.Config.EnableWebFrontEnd && baseRelative == "" {
		return PathTypeWeb
	}

	split := strings.Split(baseRelative, "/")
	if app.Config.EnableWebFrontEnd && len(split) >= 2 && split[1] == "web" {
		return PathTypeWeb
	}
	if len(split) >= 3 && split[1] == "drasl" && split[2] == "api" {
		return PathTypeAPI
	}

	return PathTypeYggdrasil
}

func (app *App) HandleYggdrasilError(err error, c *echo.Context) error {
	path_ := (*c).Request().URL.Path
	var yggdrasilError *YggdrasilError
	if errors.As(err, &yggdrasilError) {
		return (*c).JSON(yggdrasilError.Code, YggdrasilErrorResponse{
			Path:         &path_,
			Error:        yggdrasilError.Error_.ToPointer(),
			ErrorMessage: yggdrasilError.ErrorMessage.ToPointer(),
		})
	}
	var sc echo.HTTPStatusCoder
	if errors.As(err, &sc) {
		code := sc.StatusCode()
		switch code {
		case http.StatusNotFound,
			http.StatusRequestEntityTooLarge,
			http.StatusTooManyRequests,
			http.StatusMethodNotAllowed:
			return (*c).JSON(code, YggdrasilErrorResponse{Path: &path_})
		}
	}
	LogError(err, c)
	return (*c).JSON(http.StatusInternalServerError, YggdrasilErrorResponse{Path: &path_, ErrorMessage: Ptr("internal server error")})

}

func (app *App) GetTextureReader(textureType string, reader io.Reader) (io.Reader, error) {
	switch textureType {
	case TextureTypeSkin:
		return app.GetSkinReader(reader)
	case TextureTypeCape:
		return app.GetCapeReader(reader)
	default:
		return nil, fmt.Errorf("unexpected texture type: %s", textureType)
	}
}

const BASE_SKIN_WIDTH = 64
const BASE_SKIN_HEIGHT = 64
const BASE_SKIN_HEIGHT_LEGACY = 32

func (app *App) GetSkinReader(reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, NewUserError(Tr("skin must not be greater than %d pixels wide", app.Config.SkinSizeLimit))
	}

	mustBeMultipleError := NewUserError(Tr("skin size must be a multiple of %[1]d pixels wide by %[2]d or %[3]d pixels high", BASE_SKIN_WIDTH, BASE_SKIN_HEIGHT, BASE_SKIN_HEIGHT_LEGACY))
	if config.Width%BASE_SKIN_WIDTH != 0 {
		return nil, mustBeMultipleError
	}

	scale := config.Width / BASE_SKIN_WIDTH
	if config.Height != scale*BASE_SKIN_HEIGHT && config.Height != scale*BASE_SKIN_HEIGHT_LEGACY {
		return nil, mustBeMultipleError
	}

	return io.MultiReader(&header, reader), nil
}

const BASE_CAPE_WIDTH = 64
const BASE_CAPE_HEIGHT = 32

func (app *App) GetCapeReader(reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, NewUserError(Tr("cape must not be greater than %d pixels wide", app.Config.SkinSizeLimit))
	}

	mustBeMultipleError := NewUserError(Tr("cape size must be a multiple of %[1]d pixels wide by %[2]d pixels high", BASE_CAPE_WIDTH, BASE_CAPE_HEIGHT))
	if config.Width%BASE_CAPE_WIDTH != 0 {
		return nil, mustBeMultipleError
	}

	scale := config.Width / BASE_CAPE_WIDTH
	if config.Height != scale*BASE_CAPE_HEIGHT {
		return nil, mustBeMultipleError
	}

	return io.MultiReader(&header, reader), nil
}

func (app *App) ReadTexture(reader io.Reader) (*bytes.Buffer, string, error) {
	limitedReader := io.LimitReader(reader, 10e6)

	// It's fine to read the whole skin into memory here; they will almost
	// always be <1MiB, and it's nice to know the filename before writing it to
	// disk anyways.
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(limitedReader)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	hash := hex.EncodeToString(sum[:])

	return buf, hash, nil
}

func (app *App) WriteSkin(hash string, buf *bytes.Buffer) error {
	// DB state -> FS state
	skinPath := app.GetSkinPath(hash)

	// Make sure we are the only one writing to `skinPath`
	unlock := app.FSMutex.Lock(skinPath)
	defer unlock()

	_, err := os.Stat(skinPath)
	if err == nil {
		// We're good, skin already exists
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	err = os.MkdirAll(path.Dir(skinPath), os.ModePerm)
	if err != nil {
		return err
	}

	dest, err := os.Create(skinPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = buf.WriteTo(dest)
	if err != nil {
		return err
	}

	return nil
}

func (app *App) WriteCape(hash string, buf *bytes.Buffer) error {
	// DB state -> FS state
	capePath := app.GetCapePath(hash)

	// Make sure we are the only one writing to `capePath`
	unlock := app.FSMutex.Lock(capePath)
	defer unlock()

	_, err := os.Stat(capePath)
	if err == nil {
		// We're good, cape already exists
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	err = os.MkdirAll(path.Dir(capePath), os.ModePerm)
	if err != nil {
		return err
	}

	dest, err := os.Create(capePath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = buf.WriteTo(dest)
	if err != nil {
		return err
	}

	return nil
}

func (app *App) SetSkinAndSave(player *Player, reader io.Reader) error {
	oldSkinHash := UnmakeNullString(&player.SkinHash)

	var buf *bytes.Buffer
	var hash string
	if reader == nil {
		player.SkinHash = MakeNullString(nil)
	} else {
		validSkinHandle, err := app.GetSkinReader(reader)
		if err != nil {
			return err
		}

		buf, hash, err = app.ReadTexture(validSkinHandle)
		if err != nil {
			return err
		}
		player.SkinHash = MakeNullString(&hash)
	}

	err := app.DB.Save(player).Error
	if err != nil {
		return err
	}

	if buf != nil {
		err = app.WriteSkin(hash, buf)
		if err != nil {
			return err
		}
	}

	err = app.DeleteSkinIfUnused(oldSkinHash)
	if err != nil {
		return err
	}

	return nil
}

func (app *App) SetCapeAndSave(player *Player, reader io.Reader) error {
	oldCapeHash := UnmakeNullString(&player.CapeHash)

	var buf *bytes.Buffer
	var hash string
	if reader == nil {
		player.CapeHash = MakeNullString(nil)
	} else {
		validCapeHandle, err := app.GetCapeReader(reader)
		if err != nil {
			return err
		}

		buf, hash, err = app.ReadTexture(validCapeHandle)
		if err != nil {
			return err
		}
		player.CapeHash = MakeNullString(&hash)
	}

	err := app.DB.Save(player).Error
	if err != nil {
		return err
	}

	if buf != nil {
		err = app.WriteCape(hash, buf)
		if err != nil {
			return err
		}
	}

	err = app.DeleteCapeIfUnused(oldCapeHash)
	if err != nil {
		return err
	}

	return nil
}

// Delete skin if not in use
func (app *App) DeleteSkinIfUnused(hash *string) error {
	if hash == nil {
		return nil
	}

	path := app.GetSkinPath(*hash)
	unlock := app.FSMutex.Lock(path)
	defer unlock()

	var inUse bool

	err := app.DB.Model(Player{}).
		Select("count(*) > 0").
		Where("skin_hash = ?", *hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		err := os.Remove(path)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete cape if not in use
func (app *App) DeleteCapeIfUnused(hash *string) error {
	if hash == nil {
		return nil
	}

	path := app.GetCapePath(*hash)
	unlock := app.FSMutex.Lock(path)
	defer unlock()

	var inUse bool

	err := app.DB.Model(Player{}).
		Select("count(*) > 0").
		Where("cape_hash = ?", *hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		err := os.Remove(path)
		if err != nil {
			return err
		}
	}

	return nil
}

func UnsetQueryParam(urlString string, param string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Del(param)

	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

func SetQueryParam(urlString string, param string, value string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Set(param, value)

	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

func (app *App) CreateInvite() (Invite, error) {
	code, err := RandomBase62(8)
	if err != nil {
		return Invite{}, err
	}
	invite := Invite{
		Code:      code,
		CreatedAt: time.Now(),
	}
	result := app.DB.Create(&invite)
	if result.Error != nil {
		return Invite{}, result.Error
	}
	return invite, nil
}

type textureMetadata struct {
	Model string `json:"model"`
}

type texture struct {
	URL      string           `json:"url"`
	Metadata *textureMetadata `json:"metadata,omitempty"`
}

type textureMap struct {
	Skin *texture `json:"SKIN,omitempty"`
	Cape *texture `json:"CAPE,omitempty"`
}

type texturesValue struct {
	Timestamp   int64      `json:"timestamp"`
	ProfileID   string     `json:"profileId"`
	ProfileName string     `json:"profileName"`
	Textures    textureMap `json:"textures"`
}

type SessionProfileProperty struct {
	Name      string  `json:"name"`
	Value     string  `json:"value"`
	Signature *string `json:"signature,omitempty"`
}

type SessionProfileResponse struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties []SessionProfileProperty `json:"properties"`
}

func (app *App) GetFallbackSkinTexturesProperty(player *Player) (*SessionProfileProperty, error) {
	/// Forward a skin for `player` from the fallback API servers

	// If user does not have a FallbackPlayer set, don't get any skin.
	if player.FallbackPlayer == "" {
		return nil, nil
	}

	// Check whether the user's `FallbackPlayer` is a UUID or a player name.
	// If it's a UUID, remove the hyphens.
	var fallbackPlayer string
	var fallbackPlayerIsUUID bool
	_, err := uuid.Parse(player.FallbackPlayer)
	if err == nil {
		fallbackPlayerIsUUID = true
		if len(player.FallbackPlayer) == 36 {
			// user.FallbackPlayer is a UUID with hyphens
			fallbackPlayer, err = UUIDToID(player.FallbackPlayer)
			if err != nil {
				return nil, err
			}
		} else {
			// user.FallbackPlayer is a UUID without hyphens
			fallbackPlayer = player.FallbackPlayer
		}
	} else {
		// user.FallbackPlayer is a player name
		fallbackPlayerIsUUID = false
		fallbackPlayer = player.FallbackPlayer
	}

	for _, nickname := range app.FallbackAPIServerNicknames {
		fallbackAPIServer := app.FallbackAPIServers[nickname]
		if !fallbackAPIServer.Config.ForwardSkins {
			continue
		}
		var id string
		if fallbackPlayerIsUUID {
			// If we have the UUID already, use it
			id = fallbackPlayer
		} else {
			// Otherwise, we only know the player name. Query the fallback API
			// server to get the fallback player's UUID
			lowerName := strings.ToLower(fallbackPlayer)
			fallbackResponses := fallbackAPIServer.PlayerNamesToIDs(mapset.NewSet(lowerName))
			if len(fallbackResponses) == 1 && strings.EqualFold(lowerName, fallbackResponses[0].Name) {
				id = fallbackResponses[0].ID
			} else {
				continue
			}
		}

		reqURL := fallbackAPIServer.SessionGetProfileByIDURL + "/" + url.PathEscape(id)
		res, err := app.CachedGet(reqURL+"?unsigned=false", fallbackAPIServer.Config.CacheTTLSeconds)
		if err != nil {
			log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
			continue
		}

		if res.StatusCode != http.StatusOK {
			log.Printf("Request to fallback API server at %s resulted in status code %d\n", reqURL, res.StatusCode)
			continue
		}

		var profileRes SessionProfileResponse
		err = json.Unmarshal(res.BodyBytes, &profileRes)
		if err != nil {
			log.Printf("Received invalid response from fallback API server at %s\n", reqURL)
			continue
		}

		var texturesProperty *SessionProfileProperty
		for _, property := range profileRes.Properties {
			if property.Name == "textures" {
				texturesProperty = &property
				break
			}
		}
		if texturesProperty == nil {
			continue
		}
		return texturesProperty, nil
	}

	return nil, nil
}

type TextureSource int

const (
	TextureSourceNone TextureSource = iota
	TextureSourcePlayer
	TextureSourceFallback
	TextureSourceDefault // the operator's default-skin/default-cape, not vanilla's
)

type PlayerTexture struct {
	Source TextureSource
	URL    string
	Model  string // skins only
}

type PlayerTextures struct {
	// Relayed verbatim: the signature is the fallback server's, so it can't be
	// rebuilt from Skin and Cape.
	Fallback *SessionProfileProperty
	Skin     PlayerTexture
	Cape     PlayerTexture
}

// All-or-nothing: any texture of their own takes the player out of forwarding,
// and a fallback that answers bypasses the operator defaults. Only a round trip
// can say whether one will answer.
func (app *App) FallbackTexturesPossible(player *Player) bool {
	if player.SkinHash.Valid || player.CapeHash.Valid || player.FallbackPlayer == "" {
		return false
	}
	for _, nickname := range app.FallbackAPIServerNicknames {
		if app.FallbackAPIServers[nickname].Config.ForwardSkins {
			return true
		}
	}
	return false
}

// Decides the forwarding gate and the skin/cape precedence for the session
// routes, the services profile, and the previews alike.
func (app *App) ResolvePlayerTextures(player *Player) (PlayerTextures, error) {
	var resolved PlayerTextures

	if app.FallbackTexturesPossible(player) {
		property, err := app.GetFallbackSkinTexturesProperty(player)
		if err != nil {
			log.Printf("Error getting fallback textures for player %s: %s\n", player.Name, err)
		}
		if property != nil {
			resolved.Fallback = property
			if textures := app.decodeTexturesProperty(player, property); textures != nil {
				if textures.Skin != nil && textures.Skin.URL != "" {
					// Mojang omits the metadata entirely for classic skins.
					model := SkinModelClassic
					if textures.Skin.Metadata != nil {
						model = textures.Skin.Metadata.Model
					}
					resolved.Skin = PlayerTexture{Source: TextureSourceFallback, URL: textures.Skin.URL, Model: model}
				}
				if textures.Cape != nil && textures.Cape.URL != "" {
					resolved.Cape = PlayerTexture{Source: TextureSourceFallback, URL: textures.Cape.URL}
				}
			}
			return resolved, nil
		}
	}

	if player.SkinHash.Valid {
		skinURL, err := app.SkinURL(player.SkinHash.String)
		if err != nil {
			return PlayerTextures{}, err
		}
		resolved.Skin = PlayerTexture{
			Source: TextureSourcePlayer,
			URL:    skinURL,
			Model:  player.SkinModel,
		}
	} else {
		tex, err := app.defaultSkinTexture(player)
		if err != nil {
			return PlayerTextures{}, err
		}
		if tex != nil {
			resolved.Skin = *tex
		}
	}

	if player.CapeHash.Valid {
		capeURL, err := app.CapeURL(player.CapeHash.String)
		if err != nil {
			return PlayerTextures{}, err
		}
		resolved.Cape = PlayerTexture{
			Source: TextureSourcePlayer,
			URL:    capeURL,
		}
	} else {
		tex, err := app.defaultCapeTexture(player)
		if err != nil {
			return PlayerTextures{}, err
		}
		if tex != nil {
			resolved.Cape = *tex
		}
	}

	return resolved, nil
}

type PlayerPreview struct {
	SkinURL *string // nil when the player has no skin to show at all
	CapeURL *string
	Model   string // empty when only a fallback API server could say
}

func (app *App) GetPlayerPreview(player *Player) (PlayerPreview, error) {
	resolved, err := app.ResolvePlayerTextures(player)
	if err != nil {
		return PlayerPreview{}, err
	}
	preview := PlayerPreview{Model: SkinModelClassic}

	if resolved.Skin.Source != TextureSourceNone {
		preview.SkinURL = &resolved.Skin.URL
		preview.Model = resolved.Skin.Model
	} else {
		vanillaURL, slim, err := app.VanillaDefaultSkin(player)
		if err != nil {
			return PlayerPreview{}, err
		}
		preview.SkinURL = vanillaURL
		if slim {
			preview.Model = SkinModelSlim
		}
	}

	if resolved.Cape.Source != TextureSourceNone {
		preview.CapeURL = &resolved.Cape.URL
	}
	return preview, nil
}

// The texture the list avatars crop a head out of.
func (app *App) PlayerAvatarSkinURL(player *Player) (*string, error) {
	preview, err := app.GetPlayerPreview(player)
	return preview.SkinURL, err
}

func (app *App) PlayerPreviewCapeURL(player *Player) (*string, error) {
	preview, err := app.GetPlayerPreview(player)
	return preview.CapeURL, err
}

// The preview a page renders. Querying a fallback API server can take as long
// as its timeout, so this never leaves the machine: when one might answer, the
// textures are linked by route for the browser to fetch on its own and the
// model is left unknown.
func (app *App) GetPlayerPreviewLinks(player *Player) (PlayerPreview, error) {
	skinURL, err := url.JoinPath(app.FrontEndURL, "web/texture/player", player.UUID, "skin")
	if err != nil {
		return PlayerPreview{}, err
	}

	if !app.FallbackTexturesPossible(player) {
		preview, err := app.GetPlayerPreview(player)
		if err != nil {
			return PlayerPreview{}, err
		}
		if preview.SkinURL == nil {
			// The route serves the missing texture in place of a skin
			preview.SkinURL = &skinURL
		}
		return preview, nil
	}

	capeURL, err := url.JoinPath(app.FrontEndURL, "web/texture/player", player.UUID, "cape")
	if err != nil {
		return PlayerPreview{}, err
	}
	return PlayerPreview{SkinURL: &skinURL, CapeURL: &capeURL}, nil
}

// An unsupervised panic must not take the server down.
func goRecovered(what string, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic %s: %v\n", what, r)
			}
		}()
		f()
	}()
}

func (app *App) decodeTexturesProperty(player *Player, property *SessionProfileProperty) *textureMap {
	blob, err := base64.StdEncoding.DecodeString(property.Value)
	if err == nil {
		var value texturesValue
		if err = json.Unmarshal(blob, &value); err == nil {
			return &value.Textures
		}
	}
	log.Printf("Received invalid textures property for player %s from a fallback API server: %s\n", player.Name, err)
	return nil
}

func (app *App) defaultSkinGlob() string {
	return path.Join(app.Config.StateDirectory, "default-skin", "*.png")
}

func (app *App) defaultCapeGlob() string {
	return path.Join(app.Config.StateDirectory, "default-cape", "*.png")
}

func (app *App) defaultSkinTexture(player *Player) (*PlayerTexture, error) {
	chosen, err := app.ChooseFileForUser(player, app.defaultSkinGlob())
	if err != nil {
		return nil, err
	}
	if chosen == nil {
		return nil, nil
	}
	model := SkinModelClassic
	if slimSkinRegex.MatchString(*chosen) {
		model = SkinModelSlim
	}
	return &PlayerTexture{
		Source: TextureSourceDefault,
		URL:    app.TexturesURL + "/texture/default-skin/" + url.PathEscape(filepath.Base(*chosen)),
		Model:  model,
	}, nil
}

func (app *App) defaultCapeTexture(player *Player) (*PlayerTexture, error) {
	chosen, err := app.ChooseFileForUser(player, app.defaultCapeGlob())
	if err != nil {
		return nil, err
	}
	if chosen == nil {
		return nil, nil
	}
	return &PlayerTexture{
		Source: TextureSourceDefault,
		URL:    app.TexturesURL + "/texture/default-cape/" + url.PathEscape(filepath.Base(*chosen)),
	}, nil
}

func (app *App) ChooseFileForUser(player *Player, glob string) (*string, error) {
	/// Deterministically choose an arbitrary file from `glob` based on the
	//least-significant bits of the player's UUID
	filenames, err := filepath.Glob(glob)
	if err != nil {
		return nil, err
	}

	if len(filenames) == 0 {
		return nil, nil
	}

	userUUID, err := uuid.Parse(player.UUID)
	if err != nil {
		return nil, err
	}

	seed := int64(binary.BigEndian.Uint64(userUUID[8:]))
	r := mathRand.New(mathRand.NewSource(seed))

	fileIndex := r.Intn(len(filenames))

	return &filenames[fileIndex], nil
}

var slimSkinRegex = regexp.MustCompile(`.*slim\.png$`)

func (app *App) GetSkinTexturesProperty(player *Player, sign bool) (SessionProfileProperty, error) {
	id, err := UUIDToID(player.UUID)
	if err != nil {
		return SessionProfileProperty{}, err
	}

	resolved, err := app.ResolvePlayerTextures(player)
	if err != nil {
		return SessionProfileProperty{}, err
	}
	if resolved.Fallback != nil {
		property := *resolved.Fallback
		if !sign {
			property.Signature = nil
		}
		return property, nil
	}

	var skinTexture *texture
	if resolved.Skin.Source != TextureSourceNone {
		skinTexture = &texture{
			URL:      resolved.Skin.URL,
			Metadata: &textureMetadata{Model: resolved.Skin.Model},
		}
	}
	var capeTexture *texture
	if resolved.Cape.Source != TextureSourceNone {
		capeTexture = &texture{URL: resolved.Cape.URL}
	}

	texturesValue := texturesValue{
		Timestamp:   time.Now().UnixNano(),
		ProfileID:   id,
		ProfileName: player.Name,
		Textures: textureMap{
			Skin: skinTexture,
			Cape: capeTexture,
		},
	}
	texturesValueBlob, err := json.Marshal(texturesValue)
	if err != nil {
		return SessionProfileProperty{}, err
	}

	texturesValueBase64 := base64.StdEncoding.EncodeToString(texturesValueBlob)

	var texturesSignature *string
	if sign {
		signature, err := SignSHA1(app, []byte(texturesValueBase64))
		if err != nil {
			return SessionProfileProperty{}, err
		}
		signatureBase64 := base64.StdEncoding.EncodeToString(signature)
		texturesSignature = &signatureBase64
	}

	return SessionProfileProperty{
		Name:      "textures",
		Value:     texturesValueBase64,
		Signature: texturesSignature,
	}, nil
}

func MakeHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

type PlayerNameValidator struct {
	ValidPlayerNameRegex *regexp.Regexp
	MinPlayerNameLength  int
	MaxPlayerNameLength  int
}

func (validator *PlayerNameValidator) Validate(playerName string) error {
	minLength := validator.MinPlayerNameLength
	maxLength := validator.MaxPlayerNameLength
	if playerName == "" {
		return NewUserError(Tr("can't be blank"))
	}
	if len(playerName) < minLength {
		return NewUserError(TrN("can't be shorter than %d character", "can't be shorter than %d characters", minLength, minLength))
	}
	if len(playerName) > maxLength {
		return NewUserError(TrN("can't be longer than %d character", "can't be longer than %d characters", maxLength, maxLength))
	}

	if !validator.ValidPlayerNameRegex.MatchString(playerName) {
		return NewUserError(Tr("must match the following regular expression: %s", validator.ValidPlayerNameRegex))
	}
	return nil
}

type FallbackAPIServer struct {
	Config              *FallbackAPIServerConfig
	PlayerNameToIDCache mo.Option[*ristretto.Cache]
	PlayerNameToIDJobCh chan []playerNameToIDJob

	SessionGetProfileByIDURL string
	SessionVerifyURL         string
	ProfilesGetManyByNameURL string
	PlayerCertificateKeys    mapset.Set[rsa.PublicKey]
	ProfilePropertyKeys      mapset.Set[rsa.PublicKey]

	SkinDomains         mapset.Set[string]
	GetTextureValidURIs mapset.Set[string]

	PlayerNameValidator PlayerNameValidator
}

func fetchPublicKeys(url string) (mapset.Set[rsa.PublicKey], mapset.Set[rsa.PublicKey], error) {
	playerCertificateKeys := mapset.NewSet[rsa.PublicKey]()
	profilePropertyKeys := mapset.NewSet[rsa.PublicKey]()

	res, err := MakeHTTPClient().Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't access fallback API server at %s: %s\n", url, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("request to fallback API server at %s resulted in status code %d\n", url, res.StatusCode)
	}

	var publicKeysRes PublicKeysResponse
	err = json.NewDecoder(res.Body).Decode(&publicKeysRes)
	if err != nil {
		return nil, nil, fmt.Errorf("received invalid response from fallback API server at %s\n", url)
	}

	for _, serializedKey := range publicKeysRes.ProfilePropertyKeys {
		publicKey, err := SerializedKeyToPublicKey(serializedKey)
		if err != nil {
			log.Printf("Received invalid profile property key from fallback API server at %s: %s\n", url, err)
			continue
		}
		profilePropertyKeys.Add(*publicKey)
	}
	for _, serializedKey := range publicKeysRes.PlayerCertificateKeys {
		publicKey, err := SerializedKeyToPublicKey(serializedKey)
		if err != nil {
			log.Printf("Received invalid player certificate key from fallback API server at %s: %s\n", url, err)
			continue
		}
		playerCertificateKeys.Add(*publicKey)
	}
	log.Printf("Fetched public keys from fallback API server at %s", url)
	return playerCertificateKeys, profilePropertyKeys, nil
}

func parsePEMRSAPublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func untemplateURI(templatedURI string, template string) string {
	return strings.TrimRight(strings.ReplaceAll(templatedURI, "{"+template+"}", ""), "/")
}

func NewFallbackAPIServer(config *FallbackAPIServerConfig) (FallbackAPIServer, error) {
	playerNameToIDCache := mo.None[*ristretto.Cache]()
	if config.CacheTTLSeconds > 0 {
		cache, err := ristretto.NewCache(DefaultRistrettoConfig)
		if err != nil {
			return FallbackAPIServer{}, err
		}
		playerNameToIDCache = mo.Some(cache)
	}

	var sessionGetProfileByIDURL string
	var sessionVerifyURL string
	var profilesGetManyByNameURL string
	playerCertificateKeys := mapset.NewSet[rsa.PublicKey]()
	profilePropertyKeys := mapset.NewSet[rsa.PublicKey]()
	skinDomains := mapset.NewSet[string]()
	getTextureValidURIs := mapset.NewSet[string]()

	if discovery, ok := config.URLs.Arg1(); ok {
		discoveryURL := discovery.DiscoveryMinecraftClientURL
		res, err := MakeHTTPClient().Get(discoveryURL)
		if err != nil {
			return FallbackAPIServer{}, err
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			return FallbackAPIServer{}, fmt.Errorf("%s returned status code %d", discoveryURL, res.StatusCode)
		}

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(res.Body)
		if err != nil {
			return FallbackAPIServer{}, err
		}

		var discoveryResponse DiscoveryResponse
		err = json.Unmarshal(buf.Bytes(), &discoveryResponse)
		if err != nil {
			return FallbackAPIServer{}, err
		}

		sessionGetProfileByIDURL = untemplateURI(discoveryResponse.Discovery.Session.Endpoints.GetProfileByID.URI, "profileId")
		sessionVerifyURL = discoveryResponse.Discovery.Session.Endpoints.Verify.URI
		profilesGetManyByNameURL = discoveryResponse.Discovery.Profiles.Endpoints.GetManyByName.URI

		publicKeysURL := discoveryResponse.Discovery.Authentication.Endpoints.GetPublicKeys.URI

		playerCertificateKeys, profilePropertyKeys, err = fetchPublicKeys(publicKeysURL)
		if err != nil {
			log.Printf("Error fetching public keys from FallbackAPIServer %s: %s", config.Nickname, err)
		}

		for _, validURI := range discoveryResponse.Discovery.Profiles.Endpoints.GetTexture.ValidURIs {
			parsedURI, err := url.Parse(validURI)
			if err != nil {
				log.Printf("FallbackAPIServer %s returned invalid texture URI: %s", config.Nickname, validURI)
				continue
			}
			getTextureValidURIs.Add(validURI)
			skinDomains.Add(parsedURI.Host)
		}
	} else if authlibInjector, ok := config.URLs.Arg2(); ok {
		aliLocation := authlibInjector.AuthlibInjectorURL
		httpClient := MakeHTTPClient()
		res, err := httpClient.Get(aliLocation)
		if err != nil {
			return FallbackAPIServer{}, err
		}

		if headerLocation := res.Header.Get("X-Authlib-Injector-API-Location"); headerLocation != "" && headerLocation != aliLocation {
			aliLocation = headerLocation
			res, err = httpClient.Get(aliLocation)
			if err != nil {
				return FallbackAPIServer{}, err
			}
		}

		defer res.Body.Close()
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(res.Body)
		if err != nil {
			return FallbackAPIServer{}, err
		}

		var aliResponse authlibInjectorResponse
		err = json.Unmarshal(buf.Bytes(), &aliResponse)
		if err != nil {
			return FallbackAPIServer{}, err
		}

		sessionGetProfileByIDURL = aliLocation + "/sessionserver/session/minecraft/profile"
		sessionVerifyURL = aliLocation + "/sessionserver/session/minecraft/hasJoined"
		profilesGetManyByNameURL = aliLocation + "/api/profiles/minecraft"

		// TODO https://github.com/yushijinhun/authlib-injector/pull/279
		publicKey, err := parsePEMRSAPublicKey(aliResponse.SignaturePublickey)
		if err != nil {
			log.Printf("Received invalid public key from fallback API server %s: %s\n", config.Nickname, err)
		} else {
			playerCertificateKeys.Add(*publicKey)
			profilePropertyKeys.Add(*publicKey)
		}

		for _, skinDomain := range aliResponse.SkinDomains {
			skinDomains.Add(skinDomain)
			if strings.HasPrefix(skinDomain, ".") {
				// No way to represent wildcard subdomains in Mojang's
				// validUris style. Minecraft clients should treat the
				// following as allowing all URIs.
				getTextureValidURIs.Add("https://")
				getTextureValidURIs.Add("http://")
			} else {
				// authlib 10.0.76 checks:
				// url.startsWith(validUri.replace("{textureId}", ""))
				// So for now, this crude approach should work.
				getTextureValidURIs.Add("https://" + skinDomain + "/")
				getTextureValidURIs.Add("http://" + skinDomain + "/")
			}
		}
	} else {
		legacy := config.URLs.MustArg3()

		sessionGetProfileByIDURL = legacy.SessionURL + "/session/minecraft/profile"
		sessionVerifyURL = legacy.SessionURL + "/session/minecraft/hasJoined"
		profilesGetManyByNameURL = legacy.AccountURL + "/profiles/minecraft"

		publicKeysURL := legacy.ServicesURL + "/publickeys"
		var err error
		playerCertificateKeys, profilePropertyKeys, err = fetchPublicKeys(publicKeysURL)
		if err != nil {
			log.Printf("Error fetching public keys from FallbackAPIServer %s: %s", config.Nickname, err)
		}

		for _, skinDomain := range legacy.SkinDomains {
			skinDomains.Add(skinDomain)
			if strings.HasPrefix(skinDomain, ".") {
				getTextureValidURIs.Add("https://")
				getTextureValidURIs.Add("http://")
			} else {
				getTextureValidURIs.Add("https://" + skinDomain + "/")
				getTextureValidURIs.Add("http://" + skinDomain + "/")
			}
		}
	}

	validPlayerNameRegex, err := regexp.Compile(config.ValidPlayerNameRegex)
	if err != nil {
		return FallbackAPIServer{}, err
	}

	return FallbackAPIServer{
		Config:              config,
		PlayerNameToIDCache: playerNameToIDCache,
		PlayerNameToIDJobCh: make(chan []playerNameToIDJob),

		SessionGetProfileByIDURL: sessionGetProfileByIDURL,
		SessionVerifyURL:         sessionVerifyURL,
		ProfilesGetManyByNameURL: profilesGetManyByNameURL,
		ProfilePropertyKeys:      profilePropertyKeys,
		PlayerCertificateKeys:    playerCertificateKeys,

		SkinDomains:         skinDomains,
		GetTextureValidURIs: getTextureValidURIs,

		PlayerNameValidator: PlayerNameValidator{
			ValidPlayerNameRegex: validPlayerNameRegex,
			MinPlayerNameLength:  config.MinPlayerNameLength,
			MaxPlayerNameLength:  config.MaxPlayerNameLength,
		},
	}, nil
}

func (app *App) NewPlayerUUID(playerName string) (string, error) {
	switch app.Config.PlayerUUIDGeneration {
	case PlayerUUIDGenerationOffline:
		return OfflineUUID(playerName)
	default:
		return uuid.New().String(), nil
	}
}

func (app *App) BaseRelativePath(path_ string) (string, error) {
	if !strings.HasPrefix(path_, app.BasePath) {
		return "", fmt.Errorf("path %s is not under base path %s", path_, app.BasePath)
	}
	baseRelative := strings.TrimPrefix(path_, app.BasePath)
	return strings.TrimSuffix(baseRelative, "/"), nil
}

// Remove servers who haven't pinged for a while from the LRU
func (app *App) cleanupHeartbeatLRU() {
	now := time.Now()
	for {
		app.HeartbeatMutex.Lock()
		back := app.HeartbeatLruList.Back()
		if back == nil {
			app.HeartbeatMutex.Unlock()
			break
		}
		key := back.Value.(ServerKey)

		entry, ok := app.HeartbeatSaltMap[key]

		if !ok {
			app.HeartbeatLruList.Remove(back)
			app.HeartbeatMutex.Unlock()
			continue
		}

		if now.Sub(entry.Timestamp) > heartbeatLruTTL {
			delete(app.HeartbeatSaltMap, key)
			app.HeartbeatLruList.Remove(back)
			app.HeartbeatMutex.Unlock()
		} else {
			app.HeartbeatMutex.Unlock()
			break
		}
	}
}

func (app *App) RunPeriodicTasks() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute) // repeat every 10 minutes
		defer ticker.Stop()

		for range ticker.C {
			app.cleanupHeartbeatLRU()
		}
	}()
}
