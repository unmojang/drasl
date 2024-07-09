package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"image/png"
	"io"
	"log"
	"lukechampine.com/blake3"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ConstantsType struct {
	ConfigDirectory     string
	MaxPlayerNameLength int
	MaxUsernameLength   int
	Version             string
	License             string
	LicenseURL          string
	RepositoryURL       string
}

var Constants = &ConstantsType{
	MaxUsernameLength:   16,
	MaxPlayerNameLength: 16,
	ConfigDirectory:     DEFAULT_CONFIG_DIRECTORY,
	Version:             VERSION,
	License:             LICENSE,
	LicenseURL:          LICENSE_URL,
	RepositoryURL:       REPOSITORY_URL,
}

type CachedResponse struct {
	StatusCode int
	BodyBytes  []byte
}

func (app *App) CachedGet(url string, ttl int) (CachedResponse, error) {
	if ttl > 0 {
		cachedResponse, found := app.RequestCache.Get(url)
		if found {
			return cachedResponse.(CachedResponse), nil
		}
	}

	res, err := MakeHTTPClient().Get(url)
	if err != nil {
		return CachedResponse{}, err
	}
	defer res.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(res.Body)

	response := CachedResponse{
		StatusCode: res.StatusCode,
		BodyBytes:  buf.Bytes(),
	}

	if ttl > 0 {
		app.RequestCache.SetWithTTL(url, response, 0, time.Duration(ttl)*time.Second)
	}

	return response, nil
}

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

func GetSkinPath(app *App, hash string) string {
	dir := path.Join(app.Config.StateDirectory, "skin")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func GetCapePath(app *App, hash string) string {
	dir := path.Join(app.Config.StateDirectory, "cape")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func IsDefaultAdmin(app *App, user *User) bool {
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

var DEFAULT_ERROR_BLOB []byte = Unwrap(json.Marshal(ErrorResponse{
	ErrorMessage: Ptr("internal server error"),
}))

type ErrorResponse struct {
	Path         *string `json:"path,omitempty"`
	Error        *string `json:"error,omitempty"`
	ErrorMessage *string `json:"errorMessage,omitempty"`
}

func MakeErrorResponse(c *echo.Context, code int, error_ *string, errorMessage *string) error {
	return (*c).JSON(code, ErrorResponse{
		Path:         Ptr((*c).Request().URL.Path),
		Error:        error_,
		ErrorMessage: errorMessage,
	})
}

func IsYggdrasilPath(path_ string) bool {
	if path_ == "/" {
		return false
	}

	split := strings.Split(path_, "/")
	if len(split) >= 2 && split[1] == "web" {
		return false
	}

	return true
}

func ValidateSkin(app *App, reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if config.Width != config.Height {
		return nil, errors.New("texture must be square")
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, fmt.Errorf("texture must not be greater than %d pixels wide", app.Config.SkinSizeLimit)
	}

	return io.MultiReader(&header, reader), nil
}

func ValidateCape(app *App, reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if config.Width != 2*config.Height {
		return nil, errors.New("cape's width must be twice its height")
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, fmt.Errorf("texture must not be greater than %d pixels wide", app.Config.SkinSizeLimit)
	}

	return io.MultiReader(&header, reader), nil
}

func ReadTexture(app *App, reader io.Reader) (*bytes.Buffer, string, error) {
	limitedReader := io.LimitReader(reader, 10e6)

	// It's fine to read the whole skin into memory here; they will almost
	// always be <1MiB, and it's nice to know the filename before writing it to
	// disk anyways.
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(limitedReader)
	if err != nil {
		return nil, "", err
	}
	sum := blake3.Sum256(buf.Bytes())
	hash := hex.EncodeToString(sum[:])

	return buf, hash, nil
}

func WriteSkin(app *App, hash string, buf *bytes.Buffer) error {
	// DB state -> FS state
	skinPath := GetSkinPath(app, hash)

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

func WriteCape(app *App, hash string, buf *bytes.Buffer) error {
	// DB state -> FS state
	capePath := GetCapePath(app, hash)

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

func SetSkinAndSave(app *App, user *User, reader io.Reader) error {
	oldSkinHash := UnmakeNullString(&user.SkinHash)

	var buf *bytes.Buffer
	var hash string
	if reader == nil {
		user.SkinHash = MakeNullString(nil)
	} else {
		validSkinHandle, err := ValidateSkin(app, reader)
		if err != nil {
			return err
		}

		buf, hash, err = ReadTexture(app, validSkinHandle)
		if err != nil {
			return err
		}
		user.SkinHash = MakeNullString(&hash)
	}

	err := app.DB.Save(user).Error
	if err != nil {
		return err
	}

	if buf != nil {
		err = WriteSkin(app, hash, buf)
		if err != nil {
			return err
		}
	}

	err = DeleteSkinIfUnused(app, oldSkinHash)
	if err != nil {
		return err
	}

	return nil
}

func SetCapeAndSave(app *App, user *User, reader io.Reader) error {
	oldCapeHash := UnmakeNullString(&user.CapeHash)

	var buf *bytes.Buffer
	var hash string
	if reader == nil {
		user.CapeHash = MakeNullString(nil)
	} else {
		validCapeHandle, err := ValidateCape(app, reader)
		if err != nil {
			return err
		}

		buf, hash, err = ReadTexture(app, validCapeHandle)
		if err != nil {
			return err
		}
		user.CapeHash = MakeNullString(&hash)
	}

	err := app.DB.Save(user).Error
	if err != nil {
		return err
	}

	if buf != nil {
		err = WriteCape(app, hash, buf)
		if err != nil {
			return err
		}
	}

	err = DeleteCapeIfUnused(app, oldCapeHash)
	if err != nil {
		return err
	}

	return nil
}

// Delete skin if not in use
func DeleteSkinIfUnused(app *App, hash *string) error {
	if hash == nil {
		return nil
	}

	path := GetSkinPath(app, *hash)
	unlock := app.FSMutex.Lock(path)
	defer unlock()

	var inUse bool

	err := app.DB.Model(User{}).
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
func DeleteCapeIfUnused(app *App, hash *string) error {
	if hash == nil {
		return nil
	}

	path := GetCapePath(app, *hash)
	unlock := app.FSMutex.Lock(path)
	defer unlock()

	var inUse bool

	err := app.DB.Model(User{}).
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

func DeleteUser(app *App, user *User) error {
	oldSkinHash := UnmakeNullString(&user.SkinHash)
	oldCapeHash := UnmakeNullString(&user.CapeHash)
	err := app.DB.Delete(&user).Error
	if err != nil {
		return err
	}

	err = DeleteSkinIfUnused(app, oldSkinHash)
	if err != nil {
		return err
	}

	err = DeleteCapeIfUnused(app, oldCapeHash)
	if err != nil {
		return err
	}

	return nil
}

func StripQueryParam(urlString string, param string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Del(param)

	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

func (app *App) InvalidateUser(db *gorm.DB, user *User) error {
	result := db.Model(Client{}).Where("user_uuid = ?", user.UUID).Update("version", gorm.Expr("version + ?", 1))
	return result.Error
}

func (app *App) SetIsLocked(db *gorm.DB, user *User, isLocked bool) error {
	user.IsLocked = isLocked
	if isLocked {
		user.BrowserToken = MakeNullString(nil)
		err := app.InvalidateUser(db, user)
		if err != nil {
			return err
		}
	}
	return nil
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

func GetFallbackSkinTexturesProperty(app *App, user *User) (*SessionProfileProperty, error) {
	/// Forward a skin for `user` from the fallback API servers

	// If user does not have a FallbackPlayer set, don't get any skin.
	if user.FallbackPlayer == "" {
		return nil, nil
	}

	// Check whether the user's `FallbackPlayer` is a UUID or a player name.
	// If it's a UUID, remove the hyphens.
	var fallbackPlayer string
	var fallbackPlayerIsUUID bool
	_, err := uuid.Parse(user.FallbackPlayer)
	if err == nil {
		fallbackPlayerIsUUID = true
		if len(user.FallbackPlayer) == 36 {
			// user.FallbackPlayer is a UUID with hyphens
			fallbackPlayer, err = UUIDToID(user.FallbackPlayer)
			if err != nil {
				return nil, err
			}
		} else {
			// user.FallbackPlayer is a UUID without hyphens
			fallbackPlayer = user.FallbackPlayer
		}
	} else {
		// user.FallbackPlayer is a player name
		fallbackPlayerIsUUID = false
		fallbackPlayer = user.FallbackPlayer
	}

	for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
		var id string
		if fallbackPlayerIsUUID {
			// If we have the UUID already, use it
			id = fallbackPlayer
		} else {
			// Otherwise, we only know the player name. Query the fallback API
			// server to get the fallback player's UUID
			reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "/users/profiles/minecraft/", fallbackPlayer)
			if err != nil {
				log.Println(err)
				continue
			}
			res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTLSeconds)
			if err != nil {
				log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
				continue
			}

			if res.StatusCode != http.StatusOK {
				// Be silent, 404s will be common here
				continue
			}

			var playerResponse playerNameToUUIDResponse
			err = json.Unmarshal(res.BodyBytes, &playerResponse)
			if err != nil {
				log.Printf("Received invalid response from fallback API server at %s\n", reqURL)
				continue
			}
			id = playerResponse.ID
		}
		reqURL, err := url.JoinPath(fallbackAPIServer.SessionURL, "session/minecraft/profile", id)
		if err != nil {
			log.Println(err)
			continue
		}

		res, err := app.CachedGet(reqURL+"?unsigned=false", fallbackAPIServer.CacheTTLSeconds)
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

func ChooseFileForUser(app *App, user *User, glob string) (*string, error) {
	/// Deterministically choose an arbitrary file from `glob` based on the
	//least-significant bits of the player's UUID
	filenames, err := filepath.Glob(glob)
	if err != nil {
		return nil, err
	}

	if len(filenames) == 0 {
		return nil, nil
	}

	userUUID, err := uuid.Parse(user.UUID)
	if err != nil {
		return nil, err
	}

	seed := int64(binary.BigEndian.Uint64(userUUID[8:]))
	r := rand.New(rand.NewSource(seed))

	fileIndex := r.Intn(len(filenames))

	return &filenames[fileIndex], nil
}

var slimSkinRegex = regexp.MustCompile(".*slim\\.png$")

func GetDefaultSkinTexture(app *App, user *User) *texture {
	defaultSkinDirectory := path.Join(app.Config.StateDirectory, "default-skin")
	defaultSkinGlob := path.Join(defaultSkinDirectory, "*.png")

	defaultSkinPath, err := ChooseFileForUser(app, user, defaultSkinGlob)
	if err != nil {
		log.Printf("Error choosing a file from %s: %s\n", defaultSkinGlob, err)
		return nil
	}
	if defaultSkinPath == nil {
		return nil
	}

	filename, err := filepath.Rel(defaultSkinDirectory, *defaultSkinPath)
	if err != nil {
		log.Printf("Error finding default skin %s: %s\n", *defaultSkinPath, err)
		return nil
	}

	defaultSkinURL, err := url.JoinPath(app.FrontEndURL, "web/texture/default-skin/"+filename)
	if err != nil {
		log.Printf("Error generating default skin URL for file %s\n", *defaultSkinPath)
		return nil
	}

	skinModel := SkinModelClassic
	if slimSkinRegex.MatchString(*defaultSkinPath) {
		skinModel = SkinModelSlim
	}

	return &texture{
		URL: defaultSkinURL,
		Metadata: &textureMetadata{
			Model: skinModel,
		},
	}
}

func GetDefaultCapeTexture(app *App, user *User) *texture {
	defaultCapeDirectory := path.Join(app.Config.StateDirectory, "default-cape")
	defaultCapeGlob := path.Join(defaultCapeDirectory, "*.png")

	defaultCapePath, err := ChooseFileForUser(app, user, defaultCapeGlob)
	if err != nil {
		log.Printf("Error choosing a file from %s: %s\n", defaultCapeGlob, err)
		return nil
	}
	if defaultCapePath == nil {
		return nil
	}

	filename, err := filepath.Rel(defaultCapeDirectory, *defaultCapePath)
	if err != nil {
		log.Printf("Error finding default cape %s: %s\n", *defaultCapePath, err)
		return nil
	}

	defaultCapeURL, err := url.JoinPath(app.FrontEndURL, "web/texture/default-cape/"+filename)
	if err != nil {
		log.Printf("Error generating default cape URL for file %s\n", *defaultCapePath)
		return nil
	}

	return &texture{
		URL: defaultCapeURL,
	}
}

func GetSkinTexturesProperty(app *App, user *User, sign bool) (SessionProfileProperty, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return SessionProfileProperty{}, err
	}
	if !user.SkinHash.Valid && !user.CapeHash.Valid && app.Config.ForwardSkins {
		// If the user has neither a skin nor a cape, try getting a skin from
		// Fallback API servers
		fallbackProperty, err := GetFallbackSkinTexturesProperty(app, user)
		if err != nil {
			return SessionProfileProperty{}, nil
		}
		if fallbackProperty != nil {
			if !sign {
				fallbackProperty.Signature = nil
			}
			return *fallbackProperty, nil
		}
	}

	var skinTexture *texture
	if user.SkinHash.Valid {
		skinURL, err := SkinURL(app, user.SkinHash.String)
		if err != nil {
			log.Printf("Error generating skin URL for user %s: %s\n", user.Username, err)
			return SessionProfileProperty{}, nil
		}
		skinTexture = &texture{
			URL: skinURL,
			Metadata: &textureMetadata{
				Model: user.SkinModel,
			},
		}
	} else {
		skinTexture = GetDefaultSkinTexture(app, user)
	}

	var capeTexture *texture
	if user.CapeHash.Valid {
		capeURL, err := CapeURL(app, user.CapeHash.String)
		if err != nil {
			log.Printf("Error generating cape URL for user %s: %s\n", user.Username, err)
			return SessionProfileProperty{}, nil
		}
		capeTexture = &texture{
			URL: capeURL,
		}
	} else {
		capeTexture = GetDefaultCapeTexture(app, user)
	}

	texturesValue := texturesValue{
		Timestamp:   time.Now().UnixNano(),
		ProfileID:   id,
		ProfileName: user.PlayerName,
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
