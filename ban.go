package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	MaxBanReasonMessageLength = 512
	MinCustomBanReasonID      = 60
)

type MojangBanReason struct {
	ID    int
	Label string
}

var MojangBanReasons = []MojangBanReason{
	{ID: 2, Label: Tr("Excessive false or inaccurate reports").MsgID},
	{ID: 5, Label: Tr("Hate speech or discrimination").MsgID},
	{ID: 16, Label: Tr("Hate groups or terrorism-related material").MsgID},
	{ID: 17, Label: Tr("Violating Community Standards").MsgID},
	{ID: 19, Label: Tr("Violating Community Standards").MsgID},
	{ID: 21, Label: Tr("Directed abusive or harmful language").MsgID},
	{ID: 23, Label: Tr("Violating Community Standards").MsgID},
	{ID: 25, Label: Tr("Hate groups or terrorism-related material").MsgID},
	{ID: 27, Label: Tr("Impersonation, false information, or defamation").MsgID},
	{ID: 28, Label: Tr("Illegal drugs").MsgID},
	{ID: 29, Label: Tr("Fraud").MsgID},
	{ID: 30, Label: Tr("Spam or advertising").MsgID},
	{ID: 31, Label: Tr("Violating Community Standards").MsgID},
	{ID: 32, Label: Tr("Nudity or pornography").MsgID},
	{ID: 33, Label: Tr("Sexually inappropriate content").MsgID},
	{ID: 34, Label: Tr("Extreme violence or gore").MsgID},
	{ID: 35, Label: Tr("Sexually inappropriate content").MsgID},
	{ID: 36, Label: Tr("Sexually inappropriate content").MsgID},
	{ID: 53, Label: Tr("Imminent real-world harm").MsgID},
}

var textureHashRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

func MojangBanReasonLabel(reasonID int) (string, bool) {
	for _, reason := range MojangBanReasons {
		if reason.ID == reasonID {
			return reason.Label, true
		}
	}
	return "", false
}

func normalizeBanTarget(app *App, banType BanType, target string) (string, error) {
	target = strings.TrimSpace(target)
	switch banType {
	case BanTypeUser, BanTypePlayer:
		targetUUID, err := ParseUUID(target)
		if err != nil {
			return "", NewBadRequestUserError(Tr("Invalid ban target UUID."))
		}
		return targetUUID, nil
	case BanTypeName:
		if err := app.ValidatePlayerName(target); err != nil {
			return "", NewBadRequestUserError(Tr("Invalid banned player name: %s", err))
		}
		return strings.ToLower(target), nil
	case BanTypeSkin, BanTypeCape:
		target = strings.ToLower(target)
		if !textureHashRegexp.MatchString(target) {
			return "", NewBadRequestUserError(Tr("A skin or cape ban target must be a SHA-256 hash."))
		}
		return target, nil
	default:
		return "", NewBadRequestUserError(Tr("Invalid ban type."))
	}
}

func generateCustomBanReasonID() (int, error) {
	upperBound := big.NewInt(int64(^uint32(0) >> 1))
	randomID, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return 0, err
	}
	return MinCustomBanReasonID + int(randomID.Int64())%(int(upperBound.Int64())-MinCustomBanReasonID), nil
}

func validateBanReason(reasonID *int, reasonMessage *string) (sql.NullInt64, sql.NullString, error) {
	message := ""
	if reasonMessage != nil {
		message = strings.TrimSpace(*reasonMessage)
		if len(message) > MaxBanReasonMessageLength {
			return sql.NullInt64{}, sql.NullString{}, NewBadRequestUserError(Tr("Ban reason messages may not exceed %d characters.", MaxBanReasonMessageLength))
		}
	}

	if reasonID == nil {
		if message == "" {
			return sql.NullInt64{}, sql.NullString{}, NewBadRequestUserError(Tr("A custom ban reason message is required."))
		}
		generatedID, err := generateCustomBanReasonID()
		if err != nil {
			return sql.NullInt64{}, sql.NullString{}, err
		}
		reasonID = &generatedID
	}

	if _, known := MojangBanReasonLabel(*reasonID); !known {
		if *reasonID < MinCustomBanReasonID {
			return sql.NullInt64{}, sql.NullString{}, NewBadRequestUserError(Tr("Custom ban reason IDs must be at least %d.", MinCustomBanReasonID))
		}
		if message == "" {
			return sql.NullInt64{}, sql.NullString{}, NewBadRequestUserError(Tr("A reason message is required for a custom ban reason ID."))
		}
	}

	return sql.NullInt64{Int64: int64(*reasonID), Valid: true}, MakeNullString(func() *string {
		if message == "" {
			return nil
		}
		return &message
	}()), nil
}

func (app *App) CreateBan(
	banType BanType,
	target string,
	reasonID *int,
	reasonMessage *string,
	expiresAt *time.Time,
) (Ban, error) {
	if !IsValidBanType(banType) {
		return Ban{}, NewBadRequestUserError(Tr("Invalid ban type."))
	}

	normalizedTarget, err := normalizeBanTarget(app, banType, target)
	if err != nil {
		return Ban{}, err
	}

	ban := Ban{
		ID:     uuid.NewString(),
		Type:   banType,
		Target: normalizedTarget,
	}

	switch banType {
	case BanTypeUser, BanTypePlayer:
		if banType == BanTypePlayer {
			var player Player
			if err := app.DB.Preload("User").First(&player, "uuid = ?", normalizedTarget).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return Ban{}, NewBadRequestUserError(Tr("Player not found."))
				}
				return Ban{}, err
			}
			if player.User.IsAdmin {
				return Ban{}, NewBadRequestUserError(Tr("Administrators cannot be banned."))
			}
		} else {
			var user User
			if err := app.DB.First(&user, "uuid = ?", normalizedTarget).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return Ban{}, NewBadRequestUserError(Tr("User not found."))
				}
				return Ban{}, err
			}
			if user.IsAdmin {
				return Ban{}, NewBadRequestUserError(Tr("Administrators cannot be banned."))
			}
		}

		ban.ReasonID, ban.ReasonMessage, err = validateBanReason(reasonID, reasonMessage)
		if err != nil {
			return Ban{}, err
		}
		if expiresAt != nil {
			if !expiresAt.After(time.Now()) {
				return Ban{}, NewBadRequestUserError(Tr("A temporary ban must expire in the future."))
			}
			ban.ExpiresAt = sql.NullTime{Time: expiresAt.UTC(), Valid: true}
		}
	case BanTypeName, BanTypeSkin, BanTypeCape:
		if reasonID != nil || reasonMessage != nil || expiresAt != nil {
			return Ban{}, NewBadRequestUserError(Tr("Name, skin, and cape bans do not accept reasons or expiration dates."))
		}
	}

	if err := app.DeleteExpiredBans(app.DB); err != nil {
		return Ban{}, err
	}

	var removedSkin, removedCape bool
	err = app.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&ban).Error; err != nil {
			if IsErrorUniqueFailed(err) {
				return NewBadRequestUserError(Tr("That target is already banned."))
			}
			return err
		}

		if ban.Type == BanTypeName {
			if err := tx.Model(&Player{}).
				Where("name = ?", ban.Target).
				Update("forced_name_change_ban_id", ban.ID).Error; err != nil {
				return err
			}
		}
		if ban.Type == BanTypeSkin {
			var skinCount int64
			if err := tx.Model(&Player{}).Where("skin_hash = ?", ban.Target).Count(&skinCount).Error; err != nil {
				return err
			}
			removedSkin = skinCount > 0
			if removedSkin {
				if err := tx.Model(&Player{}).
					Where("skin_hash = ?", ban.Target).
					Updates(map[string]any{
						"skin_hash":                nil,
						"using_banned_skin_ban_id": ban.ID,
					}).Error; err != nil {
					return err
				}
			}
		}
		if ban.Type == BanTypeCape {
			var capeCount int64
			if err := tx.Model(&Player{}).Where("cape_hash = ?", ban.Target).Count(&capeCount).Error; err != nil {
				return err
			}
			removedCape = capeCount > 0
			if removedCape {
				if err := tx.Model(&Player{}).Where("cape_hash = ?", ban.Target).Update("cape_hash", nil).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
	if err != nil {
		return Ban{}, err
	}

	if removedSkin {
		if err := app.DeleteSkinIfUnused(&ban.Target); err != nil {
			return Ban{}, err
		}
	}
	if removedCape {
		if err := app.DeleteCapeIfUnused(&ban.Target); err != nil {
			return Ban{}, err
		}
	}

	return ban, nil
}

func (app *App) UpdateBan(
	ban *Ban,
	reasonID *int,
	reasonMessage *string,
	expiresAt *sql.NullTime,
) (Ban, error) {
	if ban.Type == BanTypeUser || ban.Type == BanTypePlayer {
		if reasonID != nil || reasonMessage != nil {
			currentReasonID := int(ban.ReasonID.Int64)
			if reasonID == nil {
				reasonID = &currentReasonID
			}
			currentMessage := UnmakeNullString(&ban.ReasonMessage)
			if reasonMessage == nil && currentMessage != nil {
				reasonMessage = currentMessage
			}
			var err error
			ban.ReasonID, ban.ReasonMessage, err = validateBanReason(reasonID, reasonMessage)
			if err != nil {
				return Ban{}, err
			}
		}
		if expiresAt != nil {
			if expiresAt.Valid && !expiresAt.Time.After(time.Now()) {
				if err := app.DB.Delete(ban).Error; err != nil {
					return Ban{}, err
				}
				return *ban, nil
			}
			if expiresAt.Valid {
				expiresAt.Time = expiresAt.Time.UTC()
			}
			ban.ExpiresAt = *expiresAt
		}
	} else if reasonID != nil || reasonMessage != nil || expiresAt != nil {
		return Ban{}, NewBadRequestUserError(Tr("Only user and player bans have reasons or expiration dates."))
	}

	if err := app.DB.Save(ban).Error; err != nil {
		return Ban{}, err
	}
	return *ban, nil
}

func (app *App) DeleteExpiredBans(db *gorm.DB) error {
	return db.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now()).Delete(&Ban{}).Error
}

func (app *App) ActiveBan(banType BanType, target string) (*Ban, error) {
	normalizedTarget, err := normalizeBanTarget(app, banType, target)
	if err != nil {
		return nil, err
	}
	var ban Ban
	err = app.DB.Where("ban_type = ? AND target = ? AND (expires_at IS NULL OR expires_at > ?)", banType, normalizedTarget, time.Now()).First(&ban).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ban, nil
}

func (app *App) ActiveMultiplayerBan(userUUID string, playerUUID string) (*Ban, error) {
	if playerUUID != "" {
		ban, err := app.ActiveBan(BanTypePlayer, playerUUID)
		if err != nil || ban != nil {
			return ban, err
		}
	}
	return app.ActiveBan(BanTypeUser, userUUID)
}

func (app *App) IsNameBanned(playerName string) (bool, error) {
	ban, err := app.ActiveBan(BanTypeName, playerName)
	return ban != nil, err
}

func (app *App) IsTextureBanned(banType BanType, textureHash string) (bool, error) {
	if banType != BanTypeSkin && banType != BanTypeCape {
		return false, NewBadRequestUserError(Tr("Invalid texture ban type."))
	}
	ban, err := app.ActiveBan(banType, textureHash)
	return ban != nil, err
}

func (app *App) EnsureNameAllowed(playerName string) error {
	banned, err := app.IsNameBanned(playerName)
	if err != nil {
		return err
	}
	if banned {
		return NewBadRequestUserError(Tr("That player name is banned."))
	}
	return nil
}

func (app *App) EnsureTextureAllowed(banType BanType, textureHash string) error {
	banned, err := app.IsTextureBanned(banType, textureHash)
	if err != nil {
		return err
	}
	if banned {
		return NewBadRequestUserError(Tr("That texture is banned."))
	}
	return nil
}

func (app *App) ProfileActions(player *Player) ([]SessionProfileAction, error) {
	actions := make([]SessionProfileAction, 0, 2)
	if player.ForcedNameChangeBanID.Valid {
		actions = append(actions, NewSessionProfileAction(ProfileActionForcedNameChange))
	}
	if player.UsingBannedSkinBanID.Valid {
		actions = append(actions, NewSessionProfileAction(ProfileActionUsingBannedSkin))
	}
	return actions, nil
}

func (app *App) CanUseMultiplayer(user *User, player *Player) (*Ban, bool, error) {
	ban, err := app.ActiveMultiplayerBan(user.UUID, player.UUID)
	if err != nil {
		return nil, false, err
	}
	nameBanned, err := app.IsNameBanned(player.Name)
	if err != nil {
		return nil, false, err
	}
	return ban, nameBanned, nil
}

func BanReasonText(ban *Ban) string {
	if ban.ReasonMessage.Valid {
		return ban.ReasonMessage.String
	}
	if ban.ReasonID.Valid {
		if label, ok := MojangBanReasonLabel(int(ban.ReasonID.Int64)); ok {
			return label
		}
		return "Code " + strconv.FormatInt(ban.ReasonID.Int64, 10)
	}
	return "No reason supplied"
}

func BanJoinMessage(ban *Ban) string {
	message := fmt.Sprintf("You are banned from online multiplayer.\nReason: %s", BanReasonText(ban))
	if ban.ExpiresAt.Valid {
		message += "\nExpires: " + ban.ExpiresAt.Time.UTC().Format(time.RFC3339)
	} else {
		message += "\nThis ban is permanent."
	}
	return message
}
