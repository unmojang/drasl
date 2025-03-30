package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"io"
	"net/http"
	"net/url"
)

type authlibInjectorLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

type authlibInjectorMeta struct {
	ImplementationName      string               `json:"implementationName"`
	ImplementationVersion   string               `json:"implementationVersion"`
	Links                   authlibInjectorLinks `json:"links"`
	ServerName              string               `json:"serverName"`
	FeatureEnableProfileKey bool                 `json:"feature.enable_profile_key"`
}

type authlibInjectorResponse struct {
	Meta                authlibInjectorMeta `json:"meta"`
	SignaturePublickey  string              `json:"signaturePublickey"`
	SignaturePublickeys []string            `json:"signaturePublickeys"`
	SkinDomains         []string            `json:"skinDomains"`
}

func authlibInjectorSerializeKey(key *rsa.PublicKey) (string, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(pubPEM[:]), nil
}

func AuthlibInjectorRoot(app *App) func(c echo.Context) error {
	skinDomains := make([]string, 0, 1+len(app.Config.FallbackAPIServers))
	skinDomains = append(skinDomains, app.Config.Domain)
	for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
		for _, skinDomain := range fallbackAPIServer.SkinDomains {
			if !Contains(skinDomains, skinDomain) {
				skinDomains = append(skinDomains, skinDomain)
			}
		}
	}

	signaturePublicKey, err := authlibInjectorSerializeKey(&app.PrivateKey.PublicKey)
	Check(err)

	signaturePublicKeys := make([]string, 0, len(app.ProfilePropertyKeys))
	for _, key := range app.ProfilePropertyKeys {
		serialized, err := authlibInjectorSerializeKey(&key)
		Check(err)
		signaturePublicKeys = append(signaturePublicKeys, serialized)
	}

	responseBlob := Unwrap(json.Marshal(authlibInjectorResponse{
		Meta: authlibInjectorMeta{
			ImplementationName:    "Drasl",
			ImplementationVersion: Constants.Version,
			Links: authlibInjectorLinks{
				Homepage: app.FrontEndURL,
				Register: Unwrap(url.JoinPath(app.FrontEndURL, "web/registration")),
			},
			ServerName:              app.Config.InstanceName,
			FeatureEnableProfileKey: true,
		},
		SignaturePublickey:  signaturePublicKey,
		SignaturePublickeys: signaturePublicKeys,
		SkinDomains:         skinDomains,
	}))

	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, responseBlob)
	}
}

func (app *App) AuthlibInjectorUploadTexture(textureType string) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, caller *User, _ *Player) error {
		playerID := c.Param("id")
		playerUUID, err := IDToUUID(playerID)
		if err != nil {
			return &YggdrasilError{Code: http.StatusBadRequest, ErrorMessage: mo.Some("Invalid UUID format")}
		}

		textureFile, err := c.FormFile("file")
		if err != nil {
			return &YggdrasilError{Code: http.StatusBadRequest, ErrorMessage: mo.Some("Missing texture file")}
		}
		textureHandle, err := textureFile.Open()
		if err != nil {
			return err
		}
		defer textureHandle.Close()
		var textureReader io.Reader = textureHandle

		var targetPlayer Player
		result := app.DB.Preload("User").First(&targetPlayer, "uuid = ?", playerUUID)
		if result.Error != nil {
			return &YggdrasilError{Code: http.StatusBadRequest, ErrorMessage: mo.Some("Player not found")}
		}

		switch textureType {
		case TextureTypeSkin:
			var model string
			switch m := c.FormValue("model"); m {
			case "slim":
				model = SkinModelSlim
			case "":
				model = SkinModelClassic
			default:
				message := fmt.Sprintf("Unknown model: %s", m)
				return &YggdrasilError{Code: http.StatusBadRequest, ErrorMessage: mo.Some(message)}
			}
			_, err = app.UpdatePlayer(
				caller,
				targetPlayer,
				nil,            // playerName
				nil,            // fallbackPlayer
				&model,         // skinModel
				&textureReader, // skinReader
				nil,            // skinURL
				false,          // deleteSkin
				nil,            // capeReader
				nil,            // capeURL
				false,          // deleteCape
			)
			if err != nil {
				return err
			}
		case TextureTypeCape:
			_, err = app.UpdatePlayer(
				caller,
				targetPlayer,
				nil,            // playerName
				nil,            // fallbackPlayer
				nil,            // skinModel
				nil,            // skinReader
				nil,            // skinURL
				false,          // deleteSkin
				&textureReader, // capeReader
				nil,            // capeURL
				false,          // deleteCape
			)
			if err != nil {
				return err
			}
		}
		return c.NoContent(http.StatusNoContent)
	})
}

func (app *App) AuthlibInjectorDeleteTexture(textureType string) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, caller *User, _ *Player) error {
		playerID := c.Param("id")
		playerUUID, err := IDToUUID(playerID)
		if err != nil {
			return &YggdrasilError{Code: http.StatusBadRequest, ErrorMessage: mo.Some("Invalid player UUID")}
		}

		var targetPlayer Player
		result := app.DB.Preload("User").First(&targetPlayer, "uuid = ?", playerUUID)
		if result.Error != nil {
			return &YggdrasilError{Code: http.StatusNotFound, ErrorMessage: mo.Some("Player not found")}
		}

		_, err = app.UpdatePlayer(
			caller,
			targetPlayer,
			nil,                            // playerName
			nil,                            // fallbackPlayer
			nil,                            // skinModel
			nil,                            // skinReader
			nil,                            // skinURL
			textureType == TextureTypeSkin, // deleteSkin
			nil,                            // capeReader
			nil,                            // capeURL
			textureType == TextureTypeCape, // deleteCape
		)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusNoContent)
	})
}
