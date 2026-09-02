package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

type webReportParticipant struct {
	Player        Player
	IsReporter    bool
	IsReported    bool
	AlreadyBanned bool
	Disabled      bool
}

type reportsContext struct {
	baseContext
	User    *User
	Reports []APIReport
}

type reportContext struct {
	baseContext
	User            *User
	Report          Report
	APIReport       APIReport
	Evidence        []ReportEvidenceMessage
	Participants    []webReportParticipant
	MojangReasons   []MojangBanReason
	NameBanActive   bool
	SkinBanActive   bool
	CapeBanActive   bool
	ActionAvailable bool
}

func webReportError(returnURL string, err error) error {
	var userError *UserError
	if errors.As(err, &userError) {
		return &WebError{ReturnURL: returnURL, Err: userError}
	}
	return err
}

// GET /web/admin/reports
func FrontReports(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		query := app.DB.Order("created_at DESC")
		status := strings.ToUpper(c.QueryParam("status"))
		if status == "" {
			status = string(ReportStatusOpen)
		}
		if status != "ALL" {
			if status != string(ReportStatusOpen) && status != string(ReportStatusArchived) {
				return NewBadRequestUserError(Tr("Invalid report status."))
			}
			query = query.Where("status = ?", status)
		}
		if reportType := strings.ToUpper(c.QueryParam("type")); reportType != "" && reportType != "ALL" {
			if reportType != string(ReportTypeChat) && reportType != string(ReportTypeSkin) && reportType != string(ReportTypeUsername) {
				return NewBadRequestUserError(Tr("Invalid report type."))
			}
			query = query.Where("report_type = ?", reportType)
		}
		var reports []Report
		if err := query.Find(&reports).Error; err != nil {
			return err
		}
		items := make([]APIReport, len(reports))
		for i := range reports {
			items[i] = reportToAPIReport(&reports[i])
		}
		return c.Render(http.StatusOK, "reports", reportsContext{
			baseContext: app.NewBaseContext(c), User: c.Get(CONTEXT_KEY_USER).(*User), Reports: items,
		})
	}
}

// GET /web/admin/reports/:id
func FrontReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		evidence, err := reportEvidence(report)
		if err != nil {
			return err
		}
		players, err := app.reportParticipantPlayers(report)
		if err != nil {
			return err
		}
		participants := make([]webReportParticipant, len(players))
		actionAvailable := false
		for i := range players {
			active, err := app.ActiveBan(BanTypePlayer, players[i].UUID)
			if err != nil {
				return err
			}
			participants[i] = webReportParticipant{
				Player: players[i], IsReporter: players[i].UUID == report.ReporterPlayerUUID,
				IsReported: players[i].UUID == report.ReportedPlayerUUID, AlreadyBanned: active != nil,
				Disabled: players[i].User.IsAdmin || active != nil,
			}
			if !participants[i].Disabled {
				actionAvailable = true
			}
		}
		nameBanActive := false
		if report.CapturedName.Valid {
			active, err := app.ActiveBan(BanTypeName, report.CapturedName.String)
			if err != nil {
				return err
			}
			nameBanActive = active != nil
			if report.Type == ReportTypeUsername {
				actionAvailable = !nameBanActive
			}
		}
		skinBanActive := false
		if report.CapturedSkinHash.Valid {
			active, err := app.ActiveBan(BanTypeSkin, report.CapturedSkinHash.String)
			if err != nil {
				return err
			}
			skinBanActive = active != nil
			if report.Type == ReportTypeSkin && !skinBanActive {
				actionAvailable = true
			}
		}
		capeBanActive := false
		if report.CapturedCapeHash.Valid {
			active, err := app.ActiveBan(BanTypeCape, report.CapturedCapeHash.String)
			if err != nil {
				return err
			}
			capeBanActive = active != nil
			if report.Type == ReportTypeSkin && !capeBanActive {
				actionAvailable = true
			}
		}
		return c.Render(http.StatusOK, "report", reportContext{
			baseContext: app.NewBaseContext(c), User: c.Get(CONTEXT_KEY_USER).(*User), Report: *report,
			APIReport: reportToAPIReport(report), Evidence: evidence, Participants: participants,
			MojangReasons: MojangBanReasons, NameBanActive: nameBanActive,
			SkinBanActive: skinBanActive, CapeBanActive: capeBanActive, ActionAvailable: actionAvailable,
		})
	}
}

func FrontUpdateReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return err
		}
		if report.Status != ReportStatusOpen {
			return NewWebError(getReturnURL(app, c), Tr("Archived reports are read-only."))
		}
		notes, err := validateBanInternalNotes(c.FormValue("internalNotes"))
		if err != nil {
			return webReportError(getReturnURL(app, c), err)
		}
		report.InternalNotes = notes
		if err := app.DB.Save(report).Error; err != nil {
			return err
		}
		app.setSuccessMessage(c, Tr("Report updated."))
		return c.Redirect(http.StatusSeeOther, getReturnURL(app, c))
	}
}

func FrontDismissReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		returnURL := getReturnURL(app, c)
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return webReportError(returnURL, err)
		}
		if err := app.dismissReport(report, c.Get(CONTEXT_KEY_USER).(*User)); err != nil {
			return webReportError(returnURL, err)
		}
		app.setSuccessMessage(c, Tr("Report dismissed."))
		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

func FrontActionReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		returnURL := getReturnURL(app, c)
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return webReportError(returnURL, err)
		}
		if err := c.Request().ParseForm(); err != nil {
			return NewWebError(returnURL, Tr("Invalid report action."))
		}
		request := APIReportBanRequest{
			PlayerUUIDs: c.Request().Form["playerUuid"], Texture: c.FormValue("texture"),
			InternalNotes: c.FormValue("banInternalNotes"),
		}
		if report.Type == ReportTypeChat {
			reasonChoice := c.FormValue("reasonChoice")
			if reasonChoice == "custom" {
				if customID := strings.TrimSpace(c.FormValue("customReasonId")); customID != "" {
					parsed, err := strconv.Atoi(customID)
					if err != nil {
						return NewWebError(returnURL, Tr("Custom reason ID must be an integer."))
					}
					request.ReasonID = &parsed
				}
				message := c.FormValue("reasonMessage")
				request.ReasonMessage = &message
			} else {
				parsed, err := strconv.Atoi(reasonChoice)
				if err != nil {
					return NewWebError(returnURL, Tr("Select a ban reason."))
				}
				request.ReasonID = &parsed
				request.ReasonMessage = nilIfEmpty(c.FormValue("reasonMessage"))
			}
			request.ExpiresAt, _, err = webBanExpiration(c, "duration", false)
			if err != nil {
				return webReportError(returnURL, err)
			}
		}
		if _, err := app.actionReport(report, c.Get(CONTEXT_KEY_USER).(*User), request); err != nil {
			return webReportError(returnURL, err)
		}
		app.setSuccessMessage(c, Tr("Report action applied."))
		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}

func FrontDeleteReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		returnURL := app.FrontEndURL + "/web/admin/reports?status=ARCHIVED"
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return webReportError(returnURL, err)
		}
		if report.Status != ReportStatusArchived {
			return NewWebError(returnURL, Tr("Only archived reports can be deleted."))
		}
		if err := app.DB.Delete(report).Error; err != nil {
			return err
		}
		app.setSuccessMessage(c, Tr("Report deleted."))
		return c.Redirect(http.StatusSeeOther, returnURL)
	}
}
