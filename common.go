package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"lukechampine.com/blake3"
	"os"
	"path"
	"strings"
)

type ConstantsType struct {
	MaxUsernameLength   int
	MaxPlayerNameLength int
}

var Constants = &ConstantsType{
	MaxUsernameLength:   16,
	MaxPlayerNameLength: 16,
}

// Wrap string s to lines of at most n bytes
func Wrap(s string, n int) string {
	var builder strings.Builder
	for {
		end := n
		if end > len(s) {
			end = len(s)
		}
		builder.WriteString(s[:end])
		s = s[end:]
		if len(s) > 0 {
			builder.WriteString("\n")
		} else {
			break
		}
	}
	return builder.String()
}

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func Truncate(data []byte, length int) []byte {
	if len(data) < length {
		newData := make([]byte, length)
		copy(newData, data)
		return newData
	}
	return data[:16]
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func IsErrorUniqueFailed(err error) bool {
	if err == nil {
		return false
	}
	e := errors.New("UNIQUE constraint failed")
	return errors.As(err, &e)
}

func GetSkinPath(app *App, hash string) string {
	dir := path.Join(app.Config.DataDirectory, "skin")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func GetCapePath(app *App, hash string) string {
	dir := path.Join(app.Config.DataDirectory, "cape")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func SignSHA256(app *App, plaintext []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA256, sum)
}

func SignSHA1(app *App, plaintext []byte) ([]byte, error) {
	hash := sha1.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA1, sum)
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Agent struct {
	Name    string `json:"name"`
	Version uint   `json:"version"`
}

type ErrorResponse struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
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

	switch config.Width {
	case 64:
	case 128, 256, 512:
		if !app.Config.AllowHighResolutionSkins {
			return nil, errors.New("high resolution skins are not allowed")
		}
	default:
		return nil, errors.New("invalid image dimensions")
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

	switch config.Width {
	case 64:
	case 128, 256, 512:
		if !app.Config.AllowHighResolutionSkins {
			return nil, errors.New("high resolution capes are not allowed")
		}
	default:
		return nil, errors.New("invalid image dimensions")
	}

	return io.MultiReader(&header, reader), nil
}

func SetSkin(app *App, user *User, reader io.Reader) error {
	limitedReader := io.LimitReader(reader, 10e6)

	// It's fine to read the whole skin into memory here, they will almost
	// always be <1MiB, and it's nice to know the filename before writing it to
	// disk anyways.
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(limitedReader)
	if err != nil {
		return err
	}
	sum := blake3.Sum256(buf.Bytes())
	hash := hex.EncodeToString(sum[:])

	skinPath := GetSkinPath(app, hash)
	err = os.MkdirAll(path.Dir(skinPath), os.ModePerm)
	if err != nil {
		return err
	}

	oldSkinHash := UnmakeNullString(&user.SkinHash)
	user.SkinHash = MakeNullString(&hash)

	// TODO deal with race conditions here
	// https://stackoverflow.com/questions/64564781/golang-lock-per-value
	dest, err := os.Create(skinPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = buf.WriteTo(dest)
	if err != nil {
		return err
	}

	err = app.DB.Save(&user).Error
	if err != nil {
		return err
	}

	if oldSkinHash != nil {
		err = DeleteSkin(app, hash)
		if err != nil {
			return err
		}
	}

	return nil
}

func SetCape(app *App, user *User, reader io.Reader) error {
	limitedReader := io.LimitReader(reader, 10e6)

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(limitedReader)
	if err != nil {
		return err
	}

	sum := blake3.Sum256(buf.Bytes())
	hash := hex.EncodeToString(sum[:])

	capePath := GetCapePath(app, hash)
	err = os.MkdirAll(path.Dir(capePath), os.ModePerm)
	if err != nil {
		return err
	}

	oldCapeHash := UnmakeNullString(&user.CapeHash)
	user.CapeHash = MakeNullString(&hash)

	// TODO deal with race conditions here
	// https://stackoverflow.com/questions/64564781/golang-lock-per-value
	dest, err := os.Create(capePath)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = buf.WriteTo(dest)
	if err != nil {
		return err
	}

	err = app.DB.Save(&user).Error
	if err != nil {
		return err
	}

	if oldCapeHash != nil {
		err = DeleteCape(app, hash)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete skin if not in use
func DeleteSkin(app *App, hash string) error {
	var inUse bool
	err := app.DB.Model(User{}).
		Select("count(*) > 0").
		Where("skin_hash = ?", hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		os.Remove(GetSkinPath(app, hash))
	}

	return nil
}

// Delete cape if not in use
func DeleteCape(app *App, hash string) error {
	var inUse bool
	err := app.DB.Model(User{}).
		Select("count(*) > 0").
		Where("cape_hash = ?", hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		os.Remove(GetCapePath(app, hash))
	}

	return nil
}
