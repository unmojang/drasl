package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/samber/mo"
	"gorm.io/gorm"
)

const (
	maxReportBodyBytes        = 1024 * 1024
	maxReportCommentsUTF16    = 1000
	maxReportEvidenceMessages = 40
	maxReportSelectedMessages = 4
)

var reportReasons = map[string]string{
	"GENERIC":                "I_WANT_TO_REPORT_THEM",
	"I_WANT_TO_REPORT_THEM":  "I_WANT_TO_REPORT_THEM",
	"HATE_SPEECH":            "HATE_SPEECH",
	"HARASSMENT_OR_BULLYING": "HARASSMENT_OR_BULLYING",
	"SELF_HARM_OR_SUICIDE":   "SELF_HARM_OR_SUICIDE",
	"IMMINENT_HARM":          "IMMINENT_HARM",
	"DEFAMATION_IMPERSONATION_FALSE_INFORMATION": "DEFAMATION_IMPERSONATION_FALSE_INFORMATION",
	"ALCOHOL_TOBACCO_DRUGS":                      "ALCOHOL_TOBACCO_DRUGS",
	"CHILD_SEXUAL_EXPLOITATION_OR_ABUSE":         "CHILD_SEXUAL_EXPLOITATION_OR_ABUSE",
	"TERRORISM_OR_VIOLENT_EXTREMISM":             "TERRORISM_OR_VIOLENT_EXTREMISM",
	"NON_CONSENSUAL_INTIMATE_IMAGERY":            "NON_CONSENSUAL_INTIMATE_IMAGERY",
	"SEXUALLY_INAPPROPRIATE":                     "SEXUALLY_INAPPROPRIATE",
}

type reportEnvelope struct {
	Version              *int             `json:"version"`
	ID                   string           `json:"id"`
	ReportType           string           `json:"reportType"`
	Report               json.RawMessage  `json:"report"`
	ClientInfo           reportClientInfo `json:"clientInfo"`
	ThirdPartyServerInfo reportServerInfo `json:"thirdPartyServerInfo"`
}

type reportClientInfo struct {
	ClientVersion string `json:"clientVersion"`
	Locale        string `json:"locale"`
}

type reportServerInfo struct {
	Address string `json:"address"`
}

type reportPayload struct {
	Reason          *string `json:"reason"`
	OpinionComments string  `json:"opinionComments"`
	CreatedTime     string  `json:"createdTime"`
	ReportedEntity  struct {
		ProfileID string `json:"profileId"`
	} `json:"reportedEntity"`
	SkinURL  string `json:"skinUrl"`
	Evidence struct {
		Messages json.RawMessage `json:"messages"`
	} `json:"evidence"`
}

func reportError(code int, message string) error {
	return &YggdrasilError{
		Code: code, Error_: mo.Some("CONSTRAINT_VIOLATION"), ErrorMessage: mo.Some(message),
	}
}

func selectReportProtocol(envelope *reportEnvelope) (string, ReportType, error) {
	if envelope.Version == nil {
		if envelope.ReportType != "" {
			return "", "", reportError(http.StatusBadRequest, "A versionless report cannot include reportType")
		}
		return "legacy-chat-v0", ReportTypeChat, nil
	}
	if *envelope.Version != 1 {
		return "", "", reportError(http.StatusBadRequest, "Unsupported report version")
	}
	if envelope.ReportType == "" {
		return "modern-chat-v1", ReportTypeChat, nil
	}
	switch ReportType(envelope.ReportType) {
	case ReportTypeChat, ReportTypeSkin, ReportTypeUsername:
		return "modern-multitype-v1", ReportType(envelope.ReportType), nil
	default:
		return "", "", reportError(http.StatusBadRequest, "Invalid report type")
	}
}

func normalizeReportReason(protocol string, reportType ReportType, raw *string) (sql.NullString, sql.NullString, error) {
	if reportType == ReportTypeUsername {
		if raw != nil && *raw != "" {
			return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "USERNAME reports cannot include a reason")
		}
		return sql.NullString{}, sql.NullString{}, nil
	}
	if raw == nil || *raw == "" {
		return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "Report reason is required")
	}
	canonical, ok := reportReasons[*raw]
	if !ok || *raw == "FALSE_REPORTING" {
		return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "Invalid report reason")
	}
	if protocol != "modern-multitype-v1" && (*raw == "GENERIC" || *raw == "I_WANT_TO_REPORT_THEM" || *raw == "SEXUALLY_INAPPROPRIATE") {
		return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "Report reason is not valid for this client generation")
	}
	if reportType == ReportTypeChat && canonical == "SEXUALLY_INAPPROPRIATE" {
		return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "Report reason is not valid for CHAT reports")
	}
	if reportType == ReportTypeSkin && (canonical == "IMMINENT_HARM" || canonical == "DEFAMATION_IMPERSONATION_FALSE_INFORMATION") {
		return sql.NullString{}, sql.NullString{}, reportError(http.StatusBadRequest, "Report reason is not valid for SKIN reports")
	}
	return sql.NullString{String: *raw, Valid: true}, sql.NullString{String: canonical, Valid: true}, nil
}

func snapshotReportedProfile(app *App, report *Report, player *Player) error {
	if player == nil {
		return nil
	}
	report.CapturedName = sql.NullString{String: player.Name, Valid: true}
	if player.SkinHash.Valid {
		report.CapturedSkinHash = player.SkinHash
		report.CapturedSkinModel = player.SkinModel
		if data, err := os.ReadFile(app.GetSkinPath(player.SkinHash.String)); err == nil {
			report.CapturedSkinData = data
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if player.CapeHash.Valid {
		report.CapturedCapeHash = player.CapeHash
		if data, err := os.ReadFile(app.GetCapePath(player.CapeHash.String)); err == nil {
			report.CapturedCapeData = data
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func parseModernEvidence(app *App, raw json.RawMessage, targetUUID string) ([]reportEvidenceMessage, error) {
	var messages []modernReportMessage
	if len(raw) == 0 || json.Unmarshal(raw, &messages) != nil {
		return nil, reportError(http.StatusBadRequest, "Chat evidence with messages is required")
	}
	if len(messages) < 1 || len(messages) > maxReportEvidenceMessages {
		return nil, reportError(http.StatusBadRequest, "Chat evidence must contain between 1 and 40 messages")
	}
	results := make([]reportEvidenceMessage, len(messages))
	selected := 0
	for i := range messages {
		author, err := ParseUUID(messages[i].ProfileID)
		if err != nil {
			return nil, reportError(http.StatusBadRequest, "Chat evidence contains an invalid player UUID")
		}
		if _, err := ParseUUID(messages[i].SessionID); err != nil || messages[i].Timestamp.IsZero() || len(messages[i].LastSeen) > 20 {
			return nil, reportError(http.StatusBadRequest, "Chat evidence contains an invalid session, timestamp, or last-seen list")
		}
		for _, reference := range messages[i].LastSeen {
			if _, err := decodeReportSignature(reference); err != nil {
				return nil, reportError(http.StatusBadRequest, "Chat evidence contains an invalid last-seen signature")
			}
		}
		if messages[i].MessageReported {
			selected++
			if author != targetUUID {
				return nil, reportError(http.StatusBadRequest, "Only messages authored by the reported player can be selected")
			}
		}
		results[i] = verifyModernMessage(app, &messages[i])
	}
	if selected < 1 || selected > maxReportSelectedMessages {
		return nil, reportError(http.StatusBadRequest, "A chat report must select between 1 and 4 messages")
	}
	markModernChainProblems(results)
	return results, nil
}

func parseLegacyEvidence(app *App, raw json.RawMessage, targetUUID string) ([]reportEvidenceMessage, error) {
	var messages []legacyReportMessage
	if len(raw) == 0 || json.Unmarshal(raw, &messages) != nil {
		return nil, reportError(http.StatusBadRequest, "Legacy chat evidence with messages is required")
	}
	if len(messages) < 1 || len(messages) > maxReportEvidenceMessages {
		return nil, reportError(http.StatusBadRequest, "Chat evidence must contain between 1 and 40 messages")
	}
	results := make([]reportEvidenceMessage, len(messages))
	selected := 0
	for i := range messages {
		author, err := ParseUUID(messages[i].Header.ProfileID)
		if err != nil || messages[i].Body.Timestamp.IsZero() || len(messages[i].Body.LastSeenSignatures) > 5 {
			return nil, reportError(http.StatusBadRequest, "Legacy chat evidence contains invalid metadata")
		}
		for _, reference := range messages[i].Body.LastSeenSignatures {
			if _, err := ParseUUID(reference.ProfileID); err != nil {
				return nil, reportError(http.StatusBadRequest, "Legacy chat evidence contains an invalid last-seen player")
			}
			if _, err := decodeReportSignature(reference.Signature); err != nil {
				return nil, reportError(http.StatusBadRequest, "Legacy chat evidence contains an invalid last-seen signature")
			}
		}
		if messages[i].MessageReported {
			selected++
			if author != targetUUID {
				return nil, reportError(http.StatusBadRequest, "Only messages authored by the reported player can be selected")
			}
		}
		results[i] = verifyLegacyMessage(app, &messages[i])
	}
	if selected < 1 || selected > maxReportSelectedMessages {
		return nil, reportError(http.StatusBadRequest, "A chat report must select between 1 and 4 messages")
	}
	markLegacyChainProblems(messages, results)
	return results, nil
}

func markLegacyChainProblems(source []legacyReportMessage, messages []reportEvidenceMessage) {
	bySignature := make(map[string]int, len(messages))
	for i := range messages {
		bySignature[messages[i].Signature] = i
	}
	for i := range messages {
		if previous := source[i].Header.PreviousSignature; previous != nil {
			if referenced, ok := bySignature[*previous]; ok {
				if referenced >= i || messages[referenced].ProfileID != messages[i].ProfileID || messages[referenced].Status != reportMessageVerified {
					messages[i].Status, messages[i].Problem = reportMessageBrokenChain, "legacy predecessor contradicts the included evidence"
				}
			} else {
				messages[i].OutOfWindow++
			}
		}
		for _, reference := range source[i].Body.LastSeenSignatures {
			if referenced, ok := bySignature[reference.Signature]; ok {
				claimedID, _ := ParseUUID(reference.ProfileID)
				if referenced == i || messages[referenced].ProfileID != claimedID || messages[referenced].Status != reportMessageVerified {
					messages[i].Status, messages[i].Problem = reportMessageBrokenChain, "legacy last-seen reference contradicts the included evidence"
				}
			} else {
				messages[i].OutOfWindow++
			}
		}
	}
}

// ServicesPlayerReport accepts the report formats emitted by vanilla Minecraft
// 1.19.1 and later. Minecraft 1.19.0 signed chat but did not have reporting UI.
func ServicesPlayerReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		request := c.Request()
		limited := io.LimitReader(request.Body, maxReportBodyBytes+1)
		raw, err := io.ReadAll(limited)
		if err != nil {
			return err
		}
		if len(raw) > maxReportBodyBytes {
			return reportError(http.StatusRequestEntityTooLarge, "Report body is too large")
		}

		var envelope reportEnvelope
		if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Report) == 0 {
			return reportError(http.StatusBadRequest, "Malformed report request")
		}
		protocol, reportType, err := selectReportProtocol(&envelope)
		if err != nil {
			return err
		}
		reportID, err := ParseUUID(envelope.ID)
		if err != nil || uuid.MustParse(reportID).Version() != 4 {
			return reportError(http.StatusBadRequest, "Report ID must be a UUID version 4")
		}

		digestBytes := sha256.Sum256(raw)
		digest := hex.EncodeToString(digestBytes[:])
		var existing Report
		find := app.DB.First(&existing, "id = ?", reportID)
		if find.Error == nil {
			player := c.Get(CONTEXT_KEY_PLAYER).(*Player)
			if existing.ReporterPlayerUUID == player.UUID && existing.PayloadDigest == digest {
				return c.NoContent(http.StatusOK)
			}
			return reportError(http.StatusConflict, "Report ID is already in use")
		}
		if !errors.Is(find.Error, gorm.ErrRecordNotFound) {
			return find.Error
		}

		var payload reportPayload
		if err := json.Unmarshal(envelope.Report, &payload); err != nil {
			return reportError(http.StatusBadRequest, "Malformed report data")
		}
		if len(utf16.Encode([]rune(payload.OpinionComments))) > maxReportCommentsUTF16 {
			return reportError(http.StatusBadRequest, "Report comments exceed 1000 characters")
		}
		if len(envelope.ClientInfo.ClientVersion) > 128 || len(envelope.ClientInfo.Locale) > 32 || len(envelope.ThirdPartyServerInfo.Address) > 512 {
			return reportError(http.StatusBadRequest, "Report metadata is too long")
		}
		reportCreatedAt := time.Now().UTC()
		if payload.CreatedTime != "" {
			reportCreatedAt, err = time.Parse(time.RFC3339Nano, payload.CreatedTime)
			if err != nil {
				return reportError(http.StatusBadRequest, "Invalid report creation time")
			}
		}
		targetUUID, err := ParseUUID(payload.ReportedEntity.ProfileID)
		if err != nil {
			return reportError(http.StatusBadRequest, "Invalid reported player UUID")
		}
		reporter := c.Get(CONTEXT_KEY_PLAYER).(*Player)
		if reporter.UUID == targetUUID {
			return reportError(http.StatusBadRequest, "You cannot report yourself")
		}
		rawReason, reason, err := normalizeReportReason(protocol, reportType, payload.Reason)
		if err != nil {
			return err
		}
		if reportType == ReportTypeUsername && strings.TrimSpace(payload.OpinionComments) == "" {
			return reportError(http.StatusBadRequest, "USERNAME reports require comments")
		}

		report := Report{
			ID: reportID, ReporterPlayerUUID: reporter.UUID, ReportedPlayerUUID: targetUUID,
			Protocol: protocol, Type: reportType, RawReason: rawReason, Reason: reason,
			OpinionComments: payload.OpinionComments, PayloadDigest: digest, Payload: raw,
			Attestation: ReportAttestationUnattested, ClientVersion: envelope.ClientInfo.ClientVersion,
			ClientLocale: envelope.ClientInfo.Locale, ServerAddress: envelope.ThirdPartyServerInfo.Address,
			ReportCreatedAt: reportCreatedAt, Status: ReportStatusOpen,
		}
		var target Player
		if result := app.DB.First(&target, "uuid = ?", targetUUID); result.Error == nil {
			if err := snapshotReportedProfile(app, &report, &target); err != nil {
				return err
			}
		} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return result.Error
		}

		switch reportType {
		case ReportTypeSkin:
			if strings.TrimSpace(payload.SkinURL) == "" || len(payload.SkinURL) > 2048 {
				return reportError(http.StatusBadRequest, "SKIN reports require a valid skin URL")
			}
			report.ReportedSkinURL = sql.NullString{String: payload.SkinURL, Valid: true}
			if report.CapturedSkinHash.Valid {
				currentURL, err := app.SkinURL(report.CapturedSkinHash.String)
				if err != nil {
					return err
				}
				if currentURL != payload.SkinURL {
					report.CapturedSkinHash = sql.NullString{}
					report.CapturedSkinModel = ""
					report.CapturedSkinData = nil
				}
			}
		case ReportTypeChat:
			var messages []reportEvidenceMessage
			if protocol == "legacy-chat-v0" {
				messages, err = parseLegacyEvidence(app, payload.Evidence.Messages, targetUUID)
			} else {
				messages, err = parseModernEvidence(app, payload.Evidence.Messages, targetUUID)
			}
			if err != nil {
				return err
			}
			report.Attestation = reportAttestation(messages)
			report.EvidenceJSON, err = json.Marshal(messages)
			if err != nil {
				return err
			}
		}

		if err := app.DB.Create(&report).Error; err != nil {
			return err
		}
		return c.NoContent(http.StatusOK)
	}
}
