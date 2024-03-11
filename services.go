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
			return c.JSON(http.StatusUnauthorized, ErrorResponse{Path: Ptr(c.Request().URL.Path)})
		}

		accessTokenMatch := bearerExp.FindStringSubmatch(authorizationHeader)
		if accessTokenMatch == nil || len(accessTokenMatch) < 2 {
			return c.JSON(http.StatusUnauthorized, ErrorResponse{Path: Ptr(c.Request().URL.Path)})
		}
		accessToken := accessTokenMatch[1]

		client := app.GetClient(accessToken, StalePolicyAllow)
		if client == nil {
			return c.JSON(http.StatusUnauthorized, ErrorResponse{Path: Ptr(c.Request().URL.Path)})
		}
		user := client.User

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
	ID    string                `json:"id"`
	Name  string                `json:"name"`
	Skins []ServicesProfileSkin `json:"skins"`
	Capes []string              `json:"capes"` // TODO implement capes, they are undocumented on https://wiki.vg/Mojang_API#Profile_Information
}

func getServicesProfile(app *App, user *User) (ServicesProfile, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return ServicesProfile{}, nil
	}

	getServicesProfileSkin := func() *ServicesProfileSkin {
		if !user.SkinHash.Valid && !user.CapeHash.Valid && app.Config.ForwardSkins {
			fallbackProperty, err := app.GetFallbackSkinTexturesProperty(user)
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
					Variant: strings.ToUpper(fallbackTexturesValue.Textures.Skin.Metadata.Model),
				}
			}
		} else if user.SkinHash.Valid {
			skinURL, err := app.SkinURL(user.SkinHash.String)
			if err != nil {
				return nil
			}
			return &ServicesProfileSkin{
				ID:      user.UUID,
				State:   "ACTIVE",
				URL:     skinURL,
				Variant: strings.ToUpper(user.SkinModel),
			}
		}

		return nil
	}

	var skins []ServicesProfileSkin = []ServicesProfileSkin{}
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

// GET /minecraft/profile
// https://wiki.vg/Mojang_API#Profile_Information
func ServicesProfileInformation(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		servicesProfile, err := getServicesProfile(app, user)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, servicesProfile)
	})
}

type playerAttributesToggle struct {
	Enabled bool `json:"enabled"`
}
type playerAttributesPrivileges struct {
	OnlineChat        playerAttributesToggle `json:"onlineChat"`
	MultiplayerServer playerAttributesToggle `json:"multiplayerServer"`
	MultiplayerRealms playerAttributesToggle `json:"multiplayerRealms"`
	Telemetry         playerAttributesToggle `json:"telemetry"`
	OptionalTelemetry playerAttributesToggle `json:"optionalTelemetry"`
}
type playerAttributesProfanityFilterPreferences struct {
	ProfanityFilterOn bool `json:"profanityFilterOn"`
}
type playerAttributesBannedScopes struct{}
type playerAttributesBanStatus struct {
	BannedScopes playerAttributesBannedScopes `json:"bannedScopes"`
}
type playerAttributesResponse struct {
	Privileges                 playerAttributesPrivileges                 `json:"privileges"`
	ProfanityFilterPreferences playerAttributesProfanityFilterPreferences `json:"profanityFilterPreferences"`
	BanStatus                  playerAttributesBanStatus                  `json:"banStatus"`
}

// GET /player/attributes
// https://wiki.vg/Mojang_API#Player_Attributes
func ServicesPlayerAttributes(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, _ *User) error {
		res := playerAttributesResponse{
			Privileges: playerAttributesPrivileges{
				OnlineChat:        playerAttributesToggle{Enabled: true},
				MultiplayerServer: playerAttributesToggle{Enabled: true},
				MultiplayerRealms: playerAttributesToggle{Enabled: false},
				Telemetry:         playerAttributesToggle{Enabled: false},
				OptionalTelemetry: playerAttributesToggle{Enabled: false},
			},
			ProfanityFilterPreferences: playerAttributesProfanityFilterPreferences{
				ProfanityFilterOn: false,
			},
			BanStatus: playerAttributesBanStatus{BannedScopes: playerAttributesBannedScopes{}},
		}

		return c.JSON(http.StatusOK, res)
	})
}

type playerCertificatesKeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}
type playerCertificatesResponse struct {
	KeyPair              playerCertificatesKeyPair `json:"keyPair"`
	PublicKeySignature   string                    `json:"publicKeySignature"`
	PublicKeySignatureV2 string                    `json:"publicKeySignatureV2"`
	ExpiresAt            string                    `json:"expiresAt"`
	RefreshedAfter       string                    `json:"refreshedAfter"`
}

// POST /player/certificates
// https://wiki.vg/Mojang_API#Player_Certificates
func ServicesPlayerCertificates(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}

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
		if app.Config.TokenStaleSec > 0 {
			expiresAt = now.Add(time.Duration(app.Config.TokenStaleSec) * time.Second)
		} else {
			expiresAt = DISTANT_FUTURE
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
			KeyPair: playerCertificatesKeyPair{
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

// POST /minecraft/profile/skins
// https://wiki.vg/Mojang_API#Upload_Skin
func ServicesUploadSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		if !app.Config.AllowSkins {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Changing your skin is not allowed."))
		}

		model := strings.ToLower(c.FormValue("variant"))

		if !IsValidSkinModel(model) {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Invalid request body for skin upload"))
		}
		user.SkinModel = model

		file, err := c.FormFile("file")
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("content is marked non-null but is null"))
		}

		src, err := file.Open()
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("content is marked non-null but is null"))
		}
		defer src.Close()

		err = app.SetSkinAndSave(user, src)
		if err != nil {
			return MakeErrorResponse(&c, http.StatusBadRequest, nil, Ptr("Could not read image data."))
		}

		servicesProfile, err := getServicesProfile(app, user)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, servicesProfile)
	})
}

// DELETE /minecraft/profile/skins/active
// https://wiki.vg/Mojang_API#Reset_Skin
func ServicesResetSkin(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		err := app.SetSkinAndSave(user, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	})
}

// DELETE /minecraft/profile/capes/active
// https://wiki.vg/Mojang_API#Hide_Cape
func ServicesHideCape(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		err := app.SetCapeAndSave(user, nil)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	})
}

type nameChangeResponse struct {
	ChangedAt         string `json:"changedAt"`
	CreatedAt         string `json:"createdAt"`
	NameChangeAllowed bool   `json:"nameChangeAllowed"`
}

// GET /minecraft/profile/namechange
// https://wiki.vg/Mojang_API#Profile_Name_Change_Information
func ServicesNameChange(app *App) func(c echo.Context) error {
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

// GET /rollout/v1/msamigration
// https://wiki.vg/Mojang_API#Get_Account_Migration_Information
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

type blocklistResponse struct {
	BlockedProfiles []string `json:"blockedProfiles"`
}

// GET /privacy/blocklist
// https://wiki.vg/Mojang_API#Player_Blocklist
func ServicesBlocklist(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		res := blocklistResponse{
			BlockedProfiles: []string{},
		}
		return c.JSON(http.StatusOK, &res)
	})
}

type nameAvailabilityResponse struct {
	Status string `json:"status"`
}

// GET /minecraft/profile/name/:playerName/available
// https://wiki.vg/Mojang_API#Name_Availability
func ServicesNameAvailability(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		playerName := c.Param("playerName")
		if !app.Config.AllowChangingPlayerName {
			return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "NOT_ALLOWED"})
		}
		if err := app.ValidatePlayerName(playerName); err != nil {
			errorMessage := fmt.Sprintf("checkNameAvailability.profileName: %s, checkNameAvailability.profileName: Invalid profile name", err.Error())
			return MakeErrorResponse(&c, http.StatusBadRequest, Ptr("CONSTRAINT_VIOLATION"), Ptr(errorMessage))
		}
		var otherUser User
		result := app.DB.First(&otherUser, "player_name = ?", playerName)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "AVAILABLE"})
			}
			return result.Error
		}
		return c.JSON(http.StatusOK, nameAvailabilityResponse{Status: "DUPLICATE"})
	})
}

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

// PUT /minecraft/profile/name/:playerName
// https://wiki.vg/Mojang_API#Change_Name
func ServicesChangeName(app *App) func(c echo.Context) error {
	return withBearerAuthentication(app, func(c echo.Context, user *User) error {
		playerName := c.Param("playerName")
		if err := app.ValidatePlayerName(playerName); err != nil {
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

func SerializedKeyToPublicKey(serializedKey SerializedKey) (*rsa.PublicKey, error) {
	publicKeyDer, err := base64.StdEncoding.DecodeString(serializedKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDer)
	if err != nil {
		return nil, err
	}

	if rsaPublicKey, ok := publicKey.(*rsa.PublicKey); ok {
		return rsaPublicKey, nil
	}

	return nil, errors.New("not an RSA public key")
}

// GET /publickeys
// TODO document on wiki.vg
func ServicesPublicKeys(app *App) func(c echo.Context) error {
	serializedProfilePropertyKeys := make([]SerializedKey, 0, len(app.ProfilePropertyKeys))
	serializedPlayerCertificateKeys := make([]SerializedKey, 0, len(app.PlayerCertificateKeys))

	for _, key := range app.ProfilePropertyKeys {
		publicKeyDer := Unwrap(x509.MarshalPKIXPublicKey(&key))
		serializedKey := SerializedKey{PublicKey: base64.StdEncoding.EncodeToString(publicKeyDer)}
		serializedProfilePropertyKeys = append(serializedProfilePropertyKeys, serializedKey)
	}
	for _, key := range app.ProfilePropertyKeys {
		publicKeyDer := Unwrap(x509.MarshalPKIXPublicKey(&key))
		serializedKey := SerializedKey{PublicKey: base64.StdEncoding.EncodeToString(publicKeyDer)}
		serializedPlayerCertificateKeys = append(serializedPlayerCertificateKeys, serializedKey)
	}

	responseBlob := Unwrap(json.Marshal(PublicKeysResponse{
		PlayerCertificateKeys: serializedPlayerCertificateKeys,
		ProfilePropertyKeys:   serializedProfilePropertyKeys,
	}))

	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, responseBlob)
	}
}
