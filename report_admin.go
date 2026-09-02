package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
)

type APIReport struct {
	ReportID           string            `json:"reportId"`
	Type               ReportType        `json:"type" enums:"CHAT,SKIN,USERNAME"`
	Protocol           string            `json:"protocol"`
	ReporterPlayerUUID string            `json:"reporterPlayerUuid"`
	ReportedPlayerUUID string            `json:"reportedPlayerUuid"`
	RawReason          *string           `json:"rawReason,omitempty"`
	Reason             *string           `json:"reason,omitempty"`
	OpinionComments    string            `json:"opinionComments"`
	Attestation        ReportAttestation `json:"attestation" enums:"ATTESTED,PARTIAL,UNATTESTED"`
	CapturedName       *string           `json:"capturedName,omitempty"`
	CapturedSkinHash   *string           `json:"capturedSkinHash,omitempty"`
	CapturedSkinModel  string            `json:"capturedSkinModel,omitempty"`
	CapturedCapeHash   *string           `json:"capturedCapeHash,omitempty"`
	ReportedSkinURL    *string           `json:"reportedSkinUrl,omitempty"`
	ClientVersion      string            `json:"clientVersion,omitempty"`
	ClientLocale       string            `json:"clientLocale,omitempty"`
	ServerAddress      string            `json:"serverAddress,omitempty"`
	InternalNotes      string            `json:"internalNotes"`
	Status             ReportStatus      `json:"status" enums:"OPEN,ARCHIVED"`
	Resolution         ReportResolution  `json:"resolution,omitempty" enums:"ACTIONED,DISMISSED"`
	ReportCreatedAt    time.Time         `json:"reportCreatedAt"`
	ReceivedAt         time.Time         `json:"receivedAt"`
	UpdatedAt          time.Time         `json:"updatedAt"`
	ResolvedAt         *time.Time        `json:"resolvedAt,omitempty"`
	ResolvedByUserUUID *string           `json:"resolvedByUserUuid,omitempty"`
	ResolutionBanIDs   []string          `json:"resolutionBanIds,omitempty"`
}

type APIReportEvidence struct {
	Original json.RawMessage         `json:"original"`
	Messages []reportEvidenceMessage `json:"messages,omitempty"`
}

type APIUpdateReportRequest struct {
	InternalNotes string `json:"internalNotes" example:"Moderator-only case notes."`
}

type APIReportBanRequest struct {
	PlayerUUIDs   []string   `json:"playerUuids,omitempty"`
	Texture       string     `json:"texture,omitempty" enums:"skin,cape,both"`
	ReasonID      *int       `json:"reasonId,omitempty"`
	ReasonMessage *string    `json:"reasonMessage,omitempty"`
	InternalNotes string     `json:"internalNotes,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
}

type reportResolutionRecord struct {
	BanIDs []string `json:"banIds"`
}

func reportToAPIReport(report *Report) APIReport {
	result := APIReport{
		ReportID: report.ID, Type: report.Type, Protocol: report.Protocol,
		ReporterPlayerUUID: report.ReporterPlayerUUID, ReportedPlayerUUID: report.ReportedPlayerUUID,
		RawReason: UnmakeNullString(&report.RawReason), Reason: UnmakeNullString(&report.Reason),
		OpinionComments: report.OpinionComments, Attestation: report.Attestation,
		CapturedName: UnmakeNullString(&report.CapturedName), CapturedSkinHash: UnmakeNullString(&report.CapturedSkinHash),
		CapturedSkinModel: report.CapturedSkinModel, CapturedCapeHash: UnmakeNullString(&report.CapturedCapeHash),
		ReportedSkinURL: UnmakeNullString(&report.ReportedSkinURL), ClientVersion: report.ClientVersion,
		ClientLocale: report.ClientLocale, ServerAddress: report.ServerAddress, InternalNotes: report.InternalNotes,
		Status: report.Status, Resolution: report.Resolution, ReportCreatedAt: report.ReportCreatedAt,
		ReceivedAt: report.CreatedAt, UpdatedAt: report.UpdatedAt,
		ResolvedByUserUUID: UnmakeNullString(&report.ResolvedByUserUUID),
	}
	if report.ResolvedAt.Valid {
		resolvedAt := report.ResolvedAt.Time
		result.ResolvedAt = &resolvedAt
	}
	if len(report.ResolutionJSON) > 0 {
		var resolution reportResolutionRecord
		if json.Unmarshal(report.ResolutionJSON, &resolution) == nil {
			result.ResolutionBanIDs = resolution.BanIDs
		}
	}
	return result
}

func (app *App) findReportByID(id string) (*Report, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.Version() != 4 {
		return nil, NewBadRequestUserError(Tr("Invalid report ID."))
	}
	var report Report
	if err := app.DB.First(&report, "id = ?", parsed.String()).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewUserErrorWithCode(http.StatusNotFound, Tr("Report not found."))
		}
		return nil, err
	}
	return &report, nil
}

func reportEvidence(report *Report) ([]reportEvidenceMessage, error) {
	if len(report.EvidenceJSON) == 0 {
		return []reportEvidenceMessage{}, nil
	}
	var evidence []reportEvidenceMessage
	if err := json.Unmarshal(report.EvidenceJSON, &evidence); err != nil {
		return nil, err
	}
	return evidence, nil
}

func (app *App) reportParticipantPlayers(report *Report) ([]Player, error) {
	participantIDs := map[string]struct{}{
		report.ReporterPlayerUUID: {},
		report.ReportedPlayerUUID: {},
	}
	evidence, err := reportEvidence(report)
	if err != nil {
		return nil, err
	}
	for _, message := range evidence {
		participantIDs[message.ProfileID] = struct{}{}
	}
	ids := make([]string, 0, len(participantIDs))
	for id := range participantIDs {
		ids = append(ids, id)
	}
	var players []Player
	if err := app.DB.Preload("User").Where("uuid IN ?", ids).Find(&players).Error; err != nil {
		return nil, err
	}
	sort.Slice(players, func(i, j int) bool { return players[i].Name < players[j].Name })
	return players, nil
}

func makeReportBan(banType BanType, target string, reasonID sql.NullInt64, reasonMessage sql.NullString, notes string, expiresAt *time.Time) Ban {
	ban := Ban{ID: uuid.NewString(), Type: banType, Target: target, ReasonID: reasonID, ReasonMessage: reasonMessage, InternalNotes: notes}
	if expiresAt != nil {
		ban.ExpiresAt = sql.NullTime{Time: expiresAt.UTC(), Valid: true}
	}
	return ban
}

func activeBanExists(tx *gorm.DB, banType BanType, target string) (bool, error) {
	var count int64
	err := tx.Model(&Ban{}).Where("ban_type = ? AND target = ? AND (expires_at IS NULL OR expires_at > ?)", banType, target, time.Now()).Count(&count).Error
	return count > 0, err
}

func (app *App) actionReport(report *Report, caller *User, request APIReportBanRequest) ([]Ban, error) {
	if report.Status != ReportStatusOpen {
		return nil, NewBadRequestUserError(Tr("Only open reports can be actioned."))
	}
	notes, err := validateBanInternalNotes(request.InternalNotes)
	if err != nil {
		return nil, err
	}
	if request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now()) {
		return nil, NewBadRequestUserError(Tr("A temporary ban must expire in the future."))
	}

	var banSpecs []Ban
	switch report.Type {
	case ReportTypeChat:
		reasonID, reasonMessage, err := validateBanReason(request.ReasonID, request.ReasonMessage)
		if err != nil {
			return nil, err
		}
		participants, err := app.reportParticipantPlayers(report)
		if err != nil {
			return nil, err
		}
		allowed := make(map[string]Player, len(participants))
		for _, participant := range participants {
			allowed[participant.UUID] = participant
		}
		seen := make(map[string]struct{})
		for _, rawID := range request.PlayerUUIDs {
			playerID, err := ParseUUID(rawID)
			if err != nil {
				return nil, NewBadRequestUserError(Tr("Invalid player UUID in report action."))
			}
			player, ok := allowed[playerID]
			if !ok {
				return nil, NewBadRequestUserError(Tr("That player is not a local participant in this report."))
			}
			if player.User.IsAdmin {
				return nil, NewBadRequestUserError(Tr("Administrators cannot be banned."))
			}
			if _, duplicate := seen[playerID]; !duplicate {
				seen[playerID] = struct{}{}
				banSpecs = append(banSpecs, makeReportBan(BanTypePlayer, playerID, reasonID, reasonMessage, notes, request.ExpiresAt))
			}
		}
		if len(banSpecs) == 0 {
			return nil, NewBadRequestUserError(Tr("Select at least one local report participant."))
		}
	case ReportTypeUsername:
		if !report.CapturedName.Valid {
			return nil, NewBadRequestUserError(Tr("This report has no local name snapshot to ban."))
		}
		target, err := normalizeBanTarget(app, BanTypeName, report.CapturedName.String)
		if err != nil {
			return nil, err
		}
		banSpecs = append(banSpecs, makeReportBan(BanTypeName, target, sql.NullInt64{}, sql.NullString{}, notes, nil))
	case ReportTypeSkin:
		if request.Texture != "skin" && request.Texture != "cape" && request.Texture != "both" {
			return nil, NewBadRequestUserError(Tr("Select skin, cape, or both."))
		}
		if request.Texture == "skin" || request.Texture == "both" {
			if !report.CapturedSkinHash.Valid {
				return nil, NewBadRequestUserError(Tr("This report has no local skin snapshot to ban."))
			}
			banSpecs = append(banSpecs, makeReportBan(BanTypeSkin, report.CapturedSkinHash.String, sql.NullInt64{}, sql.NullString{}, notes, nil))
		}
		if request.Texture == "cape" || request.Texture == "both" {
			if !report.CapturedCapeHash.Valid {
				return nil, NewBadRequestUserError(Tr("This report has no local cape snapshot to ban."))
			}
			banSpecs = append(banSpecs, makeReportBan(BanTypeCape, report.CapturedCapeHash.String, sql.NullInt64{}, sql.NullString{}, notes, nil))
		}
	default:
		return nil, NewBadRequestUserError(Tr("Unsupported report type."))
	}

	if err := app.DeleteExpiredBans(app.DB); err != nil {
		return nil, err
	}
	created := make([]Ban, 0, len(banSpecs))
	err = app.DB.Transaction(func(tx *gorm.DB) error {
		var current Report
		if err := tx.First(&current, "id = ? AND status = ?", report.ID, ReportStatusOpen).Error; err != nil {
			return NewBadRequestUserError(Tr("Only open reports can be actioned."))
		}
		for i := range banSpecs {
			ban := banSpecs[i]
			alreadyBanned, err := activeBanExists(tx, ban.Type, ban.Target)
			if err != nil {
				return err
			}
			if alreadyBanned {
				return NewBadRequestUserError(Tr("A selected report target is already banned."))
			}
			if err := tx.Create(&ban).Error; err != nil {
				if IsErrorUniqueFailed(err) {
					return NewBadRequestUserError(Tr("A selected report target is already banned."))
				}
				return err
			}
			switch ban.Type {
			case BanTypeName:
				if err := tx.Model(&Player{}).Where("name = ?", ban.Target).Update("forced_name_change_ban_id", ban.ID).Error; err != nil {
					return err
				}
			case BanTypeSkin:
				if err := tx.Model(&Player{}).Where("skin_hash = ?", ban.Target).Updates(map[string]any{"skin_hash": nil, "using_banned_skin_ban_id": ban.ID}).Error; err != nil {
					return err
				}
			case BanTypeCape:
				if err := tx.Model(&Player{}).Where("cape_hash = ?", ban.Target).Update("cape_hash", nil).Error; err != nil {
					return err
				}
			}
			created = append(created, ban)
		}
		banIDs := make([]string, len(created))
		for i := range created {
			banIDs[i] = created[i].ID
		}
		resolution, err := json.Marshal(reportResolutionRecord{BanIDs: banIDs})
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		return tx.Model(&current).Updates(map[string]any{
			"status": ReportStatusArchived, "resolution": ReportResolutionActioned,
			"resolved_at": now, "resolved_by_user_uuid": caller.UUID, "resolution_json": resolution,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	for _, ban := range created {
		if ban.Type == BanTypeSkin {
			_ = app.DeleteSkinIfUnused(&ban.Target)
		}
		if ban.Type == BanTypeCape {
			_ = app.DeleteCapeIfUnused(&ban.Target)
		}
	}
	return created, nil
}

func (app *App) dismissReport(report *Report, caller *User) error {
	if report.Status != ReportStatusOpen {
		return NewBadRequestUserError(Tr("Only open reports can be dismissed."))
	}
	now := time.Now().UTC()
	result := app.DB.Model(report).Where("status = ?", ReportStatusOpen).Updates(map[string]any{
		"status": ReportStatusArchived, "resolution": ReportResolutionDismissed,
		"resolved_at": now, "resolved_by_user_uuid": caller.UUID,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return NewBadRequestUserError(Tr("Only open reports can be dismissed."))
	}
	return nil
}

// APIGetReports godoc
//
//	@Summary List player reports
//	@Tags reports
//	@Produce json
//	@Param status query string false "Report status" Enums(OPEN,ARCHIVED)
//	@Param type query string false "Report type" Enums(CHAT,SKIN,USERNAME)
//	@Success 200 {array} APIReport
//	@Router /drasl/api/v3/reports [get]
func (app *App) APIGetReports() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		query := app.DB.Order("created_at DESC")
		if status := strings.ToUpper(c.QueryParam("status")); status != "" {
			if status != string(ReportStatusOpen) && status != string(ReportStatusArchived) {
				return NewBadRequestUserError(Tr("Invalid report status."))
			}
			query = query.Where("status = ?", status)
		}
		if reportType := strings.ToUpper(c.QueryParam("type")); reportType != "" {
			if reportType != string(ReportTypeChat) && reportType != string(ReportTypeSkin) && reportType != string(ReportTypeUsername) {
				return NewBadRequestUserError(Tr("Invalid report type."))
			}
			query = query.Where("report_type = ?", reportType)
		}
		var reports []Report
		if err := query.Find(&reports).Error; err != nil {
			return err
		}
		response := make([]APIReport, len(reports))
		for i := range reports {
			response[i] = reportToAPIReport(&reports[i])
		}
		return c.JSON(http.StatusOK, response)
	}
}

func (app *App) APIGetReport() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, reportToAPIReport(report))
	}
}

func (app *App) APIGetReportEvidence() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		messages, err := reportEvidence(report)
		if err != nil {
			return err
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(http.StatusOK, APIReportEvidence{Original: json.RawMessage(report.Payload), Messages: messages})
	}
}

func (app *App) APIGetReportTexture() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		var data []byte
		switch c.Param("texture") {
		case "skin":
			data = report.CapturedSkinData
		case "cape":
			data = report.CapturedCapeData
		default:
			return NewBadRequestUserError(Tr("Invalid report texture."))
		}
		if len(data) == 0 {
			return NewUserErrorWithCode(http.StatusNotFound, Tr("Report texture not found."))
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.Blob(http.StatusOK, "image/png", data)
	}
}

func (app *App) APIUpdateReport() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		if report.Status != ReportStatusOpen {
			return NewBadRequestUserError(Tr("Archived reports are read-only."))
		}
		var request APIUpdateReportRequest
		if err := c.Bind(&request); err != nil {
			return err
		}
		notes, err := validateBanInternalNotes(request.InternalNotes)
		if err != nil {
			return err
		}
		report.InternalNotes = notes
		if err := app.DB.Save(report).Error; err != nil {
			return err
		}
		return c.JSON(http.StatusOK, reportToAPIReport(report))
	}
}

func (app *App) APIDismissReport() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		caller := c.Get(CONTEXT_KEY_USER).(*User)
		if err := app.dismissReport(report, caller); err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	}
}

func (app *App) APIActionReport() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		var request APIReportBanRequest
		if err := c.Bind(&request); err != nil {
			return err
		}
		caller := c.Get(CONTEXT_KEY_USER).(*User)
		bans, err := app.actionReport(report, caller, request)
		if err != nil {
			return err
		}
		response := make([]APIBan, len(bans))
		for i := range bans {
			response[i] = banToAPIBan(&bans[i])
		}
		return c.JSON(http.StatusCreated, response)
	}
}

func (app *App) APIDeleteReport() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		if report.Status != ReportStatusArchived {
			return NewBadRequestUserError(Tr("Only archived reports can be deleted."))
		}
		if err := app.DB.Delete(report).Error; err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	}
}
