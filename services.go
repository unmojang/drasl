package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Authenticate a user using a bearer token, and call `f` with a reference to
// the user
func withBearerAuthentication(app *App, f func(c echo.Context, user *User) error) func(c echo.Context) error {
	bearerExp := regexp.MustCompile("^Bearer (.*)$")

	return func(c echo.Context) error {
		authorizationHeader := c.Request().Header.Get("Authorization")
		if authorizationHeader == "" {
			return c.NoContent(http.StatusUnauthorized)
		}

		accessTokenMatch := bearerExp.FindStringSubmatch(authorizationHeader)
		if accessTokenMatch == nil || len(accessTokenMatch) < 2 {
			return c.NoContent(http.StatusUnauthorized)
		}
		accessToken := accessTokenMatch[1]

		var tokenPair TokenPair
		result := app.DB.Preload("User").First(&tokenPair, "access_token = ?", accessToken)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.NoContent(http.StatusUnauthorized)
			}
			return result.Error
		}
		user := tokenPair.User

		return f(c, &user)
	}
}

type ServicesProfileSkin struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	URL     string `json:"url"`
	Variant string `json:"string"`
}

type ServicesProfile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Skins []ServicesProfileSkin
	Capes []string // TODO implement capes, they are undocumented on https://wiki.vg/Mojang_API#Profile_Information
}

func getServicesProfile(app *App, user *User) (ServicesProfile, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return ServicesProfile{}, nil
	}

	getServicesProfileSkin := func() *ServicesProfileSkin {
		if !user.SkinHash.Valid && !user.CapeHash.Valid && app.Config.ForwardSkins {
			fallbackProperty, err := GetFallbackSkinTexturesProperty(app, user)
			if err != nil {
				return nil
			}

			if fallbackProperty != nil {
				fallbackTexturesValueString, err := base64.StdEncoding.DecodeString(fallbackProperty.Value)
				if err != nil {
					return nil
				}

				var fallbackTexturesValue texturesValue
				err = json.Unmarshal([]byte(fallbackTexturesValueString), &fallbackTexturesValue)
				if err != nil {
					return nil
				}

				return &ServicesProfileSkin{
					ID:      user.UUID,
					State:   "ACTIVE",
					URL:     fallbackTexturesValue.Textures.Skin.URL,
					Variant: SkinModelToVariant(fallbackTexturesValue.Textures.Skin.Metadata.Model),
				}
			}
		} else if user.SkinHash.Valid {
			return &ServicesProfileSkin{
				ID:      user.UUID,
				State:   "ACTIVE",
				URL:     SkinURL(app, user.SkinHash.String),
				Variant: SkinModelToVariant(user.SkinModel),
			}
		}

		return nil
	}

	var skins []ServicesProfileSkin
	if skin := getServicesProfileSkin(); skin != nil {
		skins = []ServicesProfileSkin{*skin}
	}

	return ServicesProfile{
		ID:    id,
		Name:  user.PlayerName,
		Skins: skins,
		Capes: []string{},
	}, nil
}

// /minecraft/profile
func ServicesProfileInformation(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		servicesProfile, err := getServicesProfile(app, user)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, servicesProfile)
	})
}

// /user/profiles/:uuid/names
func ServicesUUIDToNameHistory(app *App) func(c echo.Context) error {
	type uuidToNameHistoryResponse struct {
		Name        string  `json:"name"`
		ChangedToAt *uint64 `json:"changedToAt,omitempty"` // TODO name history
	}
	return withBearerAuthentication(app, func(c echo.Context, _ *User) error {
		uuid := c.Param("uuid")
		if len(uuid) == 32 { // UUID is missing hyphens, add them in
			var err error
			uuid, err = IDToUUID(uuid)
			if err != nil {
				return err
			}
		}

		var user User
		result := app.DB.First(&user, "uuid = ?", uuid)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				// TODO fallback servers
				return c.NoContent(http.StatusNoContent)
			}
			return result.Error
		}
		res := &[]uuidToNameHistoryResponse{{
			Name: user.PlayerName,
		}}
		return c.JSON(http.StatusOK, res)
	})
}

// /player/attributes
func ServicesPlayerAttributes(app *App) func(c echo.Context) error {
	type toggle struct {
		Enabled bool `json:"enabled"`
	}
	type privileges struct {
		OnlineChat        toggle `json:"onlineChat"`
		MultiplayerServer toggle `json:"multiplayerServer"`
		MultiplayerRealms toggle `json:"multiplayerRealms"`
		Telemetry         toggle `json:"telemetry"`
	}
	type profanityFilterPreferences struct {
		ProfanityFilterOn bool `json:"profanityFilterOn"`
	}
	type bannedScopes struct{}
	type banStatus struct {
		BannedScopes bannedScopes `json:"bannedScopes"`
	}
	type playerAttributesResponse struct {
		Privileges                 privileges                 `json:"privileges"`
		ProfanityFilterPreferences profanityFilterPreferences `json:"profanityFilterPreferences"`
		BanStatus                  banStatus                  `json:"banStatus"`
	}

	return withBearerAuthentication(app, func(c echo.Context, _ *User) error {
		res := playerAttributesResponse{
			Privileges: privileges{
				OnlineChat:        toggle{Enabled: true},
				MultiplayerServer: toggle{Enabled: true},
				MultiplayerRealms: toggle{Enabled: false},
				Telemetry:         toggle{Enabled: true},
			},
			ProfanityFilterPreferences: profanityFilterPreferences{
				ProfanityFilterOn: false,
			},
			BanStatus: banStatus{BannedScopes: bannedScopes{}},
		}

		return c.JSON(http.StatusOK, res)
	})
}

// /player/certificates
func ServicesPlayerCertificates(app *App) func(c echo.Context) error {
	type keyPair struct {
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
	}
	type playerCertificatesResponse struct {
		KeyPair              keyPair `json:"keyPair"`
		PublicKeySignature   string  `json:"publicKeySignature"`
		PublicKeySignatureV2 string  `json:"publicKeySignatureV2"`
		ExpiresAt            string  `json:"expiresAt"`
		RefreshedAfter       string  `json:"refreshedAfter"`
	}

	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}

		// TODO test this again... should this be MarshalPKCS1PublicKey?
		pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyDER,
		})

		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubDER,
		})

		now := time.Now().UTC()

		var expiresAt time.Time
		if app.Config.EnableTokenExpiry {
			expiresAt = now.AddDate(0, 0, 1) // expire in 1 day
		} else {
			// No worries, when God Emperor Brandon passes the Y2K38 Readiness
			// Act, I WILL be applying for a grant to fund emergency updates to
			// our codebase.
			expiresAt, err = time.Parse(time.RFC3339Nano, "2038-01-01:00:00.000000000Z")
		}
		if err != nil {
			return err
		}
		expiresAtMilli := expiresAt.UnixMilli()

		publicKeySignatureText := ""
		publicKeySignatureV2Text := ""

		if app.Config.SignPublicKeys {
			// publicKeySignature, used in 1.19
			// We don't just sign the public key itself---the signed data consists
			// of expiresAt timestamp as a string, concatenated with the PEM(ish)
			// encoded public key. We have to do a little extra work since the Java
			// base64 encoder wraps lines at 76 characters, while the Go encoder
			// wraps them at 64 lines.
			// In Minecraft, the buffer to be validated is built in toSerializedString in PlayerPublicKey.java:
			//		String string = "-----BEGIN RSA PUBLIC KEY-----\n" + BASE64_ENCODER.encodeToString(key.getEncoded()) + "\n-----END RSA PUBLIC KEY-----\n"
			//		return this.expiresAt.toEpochMilli() + string;
			// Here in Go, we have to recreate it byte-for-byte to create a valid signature.

			// Base64-encode the public key without any line breaks
			pubBase64 := strings.ReplaceAll(base64.StdEncoding.EncodeToString(pubDER), "\n", "")

			// Wrap the base64-encoded key to 76 characters per line
			pubBase64Wrapped := Wrap(pubBase64, 76)

			// Put it in a PEM block
			pubMojangPEM := "-----BEGIN RSA PUBLIC KEY-----\n" +
				pubBase64Wrapped +
				"\n-----END RSA PUBLIC KEY-----\n"

			// Prepend the expiresAt timestamp as a string
			signedData := []byte(fmt.Sprintf("%d%s", expiresAtMilli, pubMojangPEM))

			publicKeySignature, err := SignSHA1(app, signedData)
			if err != nil {
				return err
			}
			publicKeySignatureText = base64.StdEncoding.EncodeToString(publicKeySignature)

			// publicKeySignatureV2, used in 1.19.1+
			// Again, we don't just sign the public key, we need to
			// prepend the player's UUID and the expiresAt timestamp. In Minecraft,
			// the buffer to be validated is built in toSerializedString in
			// PlayerPublicKey.java:
			//	 byte[] bs = this.key.getEncoded();
			//	 byte[] cs = new byte[24 + bs.length];
			//	 ByteBuffer byteBuffer = ByteBuffer.wrap(cs).order(ByteOrder.BIG_ENDIAN);
			//	 byteBuffer.putLong(playerUuid.getMostSignificantBits()).putLong(playerUuid.getLeastSignificantBits()).putLong(this.expiresAt.toEpochMilli()).put(bs);
			//	 return cs;
			// The buffer is 186 bytes total.
			signedDataV2 := make([]byte, 0, 24+len(pubDER))

			// The first 16 bytes (128 bits) are the player's UUID
			userId, err := UUIDToID(user.UUID)
			if err != nil {
				return err
			}
			var uuidInt big.Int
			uuidInt.SetString(userId, 16)
			signedDataV2 = append(signedDataV2, uuidInt.Bytes()...)

			// Next 8 are UNIX millisecond timestamp of expiresAt
			expiresAtBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(expiresAtBytes, uint64(expiresAtMilli))
			signedDataV2 = append(signedDataV2, expiresAtBytes...)

			// Last is the DER-encoded public key
			signedDataV2 = append(signedDataV2, pubDER...)

			publicKeySignatureV2, err := SignSHA1(app, signedDataV2)
			if err != nil {
				return err
			}
			publicKeySignatureV2Text = base64.StdEncoding.EncodeToString(publicKeySignatureV2)
		}

		res := playerCertificatesResponse{
			KeyPair: keyPair{
				PrivateKey: string(keyPEM[:]),
				PublicKey:  string(pubPEM[:]),
			},
			PublicKeySignature:   publicKeySignatureText,
			PublicKeySignatureV2: publicKeySignatureV2Text,
			ExpiresAt:            expiresAt.Format(time.RFC3339Nano),
			RefreshedAfter:       now.Format(time.RFC3339Nano),
		}

		return c.JSON(http.StatusOK, res)
	})
}

// /minecraft/profile/skins
func ServicesUploadSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		model := strings.ToLower(c.FormValue("variant"))

		if !IsValidSkinModel(model) {
			return c.NoContent(http.StatusBadRequest)
		}
		user.SkinModel = model

		file, err := c.FormFile("file")
		if err != nil {
			return err
		}

		src, err := file.Open()
		if err != nil {
			return err
		}
		defer src.Close()

		err = SetSkinAndSave(app, user, src)
		if err != nil {
			return c.NoContent(http.StatusBadRequest) // TODO detailed errors
		}

		return c.NoContent(http.StatusOK)
	})
}

// /minecraft/profile/skins/active
func ServicesDeleteSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		err := SetSkinAndSave(app, user, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	})
}

// /minecraft/profile/capes/active
func ServicesDeleteCape(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		err := SetCapeAndSave(app, user, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	})
}

// /minecraft/profile/namechange
func ServicesNameChange(app *App) func(c echo.Context) error {
	type nameChangeResponse struct {
		ChangedAt         string `json:"changedAt"`
		CreatedAt         string `json:"createdAt"`
		NameChangeAllowed bool   `json:"nameChangeAllowed"`
	}
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		changedAt := user.NameLastChangedAt.Format(time.RFC3339Nano)
		createdAt := user.CreatedAt.Format(time.RFC3339Nano)
		res := nameChangeResponse{
			ChangedAt:         changedAt,
			CreatedAt:         createdAt,
			NameChangeAllowed: app.Config.AllowChangingPlayerName,
		}
		return c.JSON(http.StatusOK, &res)
	})
}

// /rollout/v1/msamigration
func ServicesMSAMigration(app *App) func(c echo.Context) error {
	type msaMigrationResponse struct {
		Feature string `json:"feature"`
		Rollout bool   `json:"rollout"`
	}
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		res := msaMigrationResponse{
			Feature: "msamigration",
			Rollout: false,
		}
		return c.JSON(http.StatusOK, &res)
	})
}

// /privacy/blocklist
func ServicesBlocklist(app *App) func(c echo.Context) error {
	type blocklistResponse struct {
		BlockedProfiles []string `json:"blockedProfiles"`
	}
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		res := blocklistResponse{
			BlockedProfiles: []string{},
		}
		return c.JSON(http.StatusOK, &res)
	})
}

// /minecraft/profile/name/:playerName/available
func ServicesNameAvailability(app *App) func(c echo.Context) error {
	type nameAvailabilityResponse struct {
		Status string `json:"status"`
	}
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		playerName := c.Param("playerName")
		if !app.Config.AllowChangingPlayerName {
			return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "NOT_ALLOWED"})
		}
		if err := ValidatePlayerName(app, playerName); err != nil {
			return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "NOT_ALLOWED"})
		}
		var otherUser User
		result := app.DB.First(&otherUser, "playerName = ?", playerName)
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "DUPLICATE"})
		}
		return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "AVAILABLE"})
	})
}

// /minecraft/profile/name/:playerName
func ServicesChangeName(app *App) func(c echo.Context) error {
	type changeNameErrorDetails struct {
		Status string `json:"status"`
	}
	type changeNameErrorResponse struct {
		Path             string                  `json:"path"`
		ErrorType        string                  `json:"errorType"`
		Error            string                  `json:"error"`
		Details          *changeNameErrorDetails `json:"details,omitempty"`
		ErrorMessage     string                  `json:"errorMessage"`
		DeveloperMessage string                  `json:"developerMessage"`
	}
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		playerName := c.Param("playerName")
		if err := ValidatePlayerName(app, playerName); err != nil {
			return c.JSON(http.StatusBadRequest, changeNameErrorResponse{
				Path:             c.Request().URL.Path,
				ErrorType:        "BAD REQUEST",
				Error:            "BAD REQUEST",
				ErrorMessage:     err.Error(),
				DeveloperMessage: err.Error(),
			})
		}
		if user.PlayerName != playerName {
			if app.Config.AllowChangingPlayerName {
				user.PlayerName = playerName
				user.NameLastChangedAt = time.Now()
			} else {
				message := "Changing your player name is not allowed."
				return c.JSON(http.StatusBadRequest, changeNameErrorResponse{
					Path:             c.Request().URL.Path,
					ErrorType:        "BAD REQUEST",
					Error:            "BAD REQUEST",
					ErrorMessage:     message,
					DeveloperMessage: message,
				})
			}
		}

		err := app.DB.Save(&user).Error
		if err != nil {
			if IsErrorUniqueFailed(err) {
				message := "That player name is taken."
				return c.JSON(http.StatusForbidden, changeNameErrorResponse{
					Path:      c.Request().URL.Path,
					ErrorType: "FORBIDDEN",
					Error:     "FORBIDDEN",
					Details: &changeNameErrorDetails{
						Status: "DUPLICATE",
					},
					ErrorMessage:     message,
					DeveloperMessage: message,
				})
			}
			return err
		}

		profile, err := getServicesProfile(app, user)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, profile)
	})
}

type PublicKeysResponse struct {
	PlayerCertificateKeys []SerializedKey `json:"playerCertificateKeys"`
	ProfilePropertyKeys   []SerializedKey `json:"profilePropertyKeys"`
}

type SerializedKey struct {
	PublicKey string `json:"publicKey"`
}

// /publickeys
func ServicesPublicKeys(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, PublicKeysResponse{
			PlayerCertificateKeys: app.PlayerCertificateKeys,
			ProfilePropertyKeys:   app.ProfilePropertyKeys,
		})
	}
}
