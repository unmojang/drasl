package main

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

type webReportParticipant struct {
	Player          Player
	IsReporter      bool
	IsReported      bool
	PlayerBanActive bool
	UserBanActive   bool
	Disabled        bool
}

type webReportSummary struct {
	Report
	ReportedPlayerName string
}

type webReportMessage struct {
	ReportEvidenceMessage
	PlayerName string
}

type reportsContext struct {
	baseContext
	User    *User
	Reports []webReportSummary
}

type reportContext struct {
	baseContext
	User            *User
	Report          Report
	Evidence        []webReportMessage
	Participants    []webReportParticipant
	ReporterName    string
	ReportedName    string
	SkinBanActive   bool
	CapeBanActive   bool
	ActionAvailable bool
}

func reportPlayerName(names map[string]string, id string) string {
	if name, ok := names[id]; ok {
		return name
	}
	return id
}

func reportedProfileName(report *Report, names map[string]string) string {
	if report.CapturedName.Valid {
		return report.CapturedName.String
	}
	return reportPlayerName(names, report.ReportedPlayerUUID)
}

// GET /web/admin/reports
func FrontReports(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		status := strings.ToUpper(c.QueryParam("status"))
		if status == "" {
			status = string(ReportStatusOpen)
		} else if status == "ALL" {
			status = ""
		}
		reportType := strings.ToUpper(c.QueryParam("type"))
		if reportType == "ALL" {
			reportType = ""
		}
		reports, err := app.reportsWithFilters(status, reportType)
		if err != nil {
			return err
		}
		reportedIDs := make([]string, 0, len(reports))
		for i := range reports {
			if !reports[i].CapturedName.Valid {
				reportedIDs = append(reportedIDs, reports[i].ReportedPlayerUUID)
			}
		}
		reportedNames := make(map[string]string, len(reportedIDs))
		if len(reportedIDs) > 0 {
			var players []Player
			if err := app.DB.Where("uuid IN ?", reportedIDs).Find(&players).Error; err != nil {
				return err
			}
			for i := range players {
				reportedNames[players[i].UUID] = players[i].Name
			}
		}
		items := make([]webReportSummary, len(reports))
		for i := range reports {
			items[i] = webReportSummary{Report: reports[i], ReportedPlayerName: reportedProfileName(&reports[i], reportedNames)}
		}
		return c.Render(http.StatusOK, "reports", reportsContext{
			baseContext: app.NewBaseContext(c), User: c.Get(CONTEXT_KEY_USER).(*User), Reports: items,
		})
	}
}

// GET /web/admin/reports/:id
func FrontReport(app *App) func(c *echo.Context) error {
	return app.withReport(func(c *echo.Context, report *Report) error {
		evidence, err := reportEvidence(report)
		if err != nil {
			return err
		}
		players, err := app.reportParticipantPlayers(report, evidence)
		if err != nil {
			return err
		}
		participants := make([]webReportParticipant, len(players))
		playerNames := make(map[string]string, len(players))
		actionAvailable := false
		for i := range players {
			playerNames[players[i].UUID] = players[i].Name
			playerBan, err := app.ActiveBan(BanTypePlayer, players[i].UUID)
			if err != nil {
				return err
			}
			userBan, err := app.ActiveBan(BanTypeUser, players[i].UserUUID)
			if err != nil {
				return err
			}
			participants[i] = webReportParticipant{
				Player: players[i], IsReporter: players[i].UUID == report.ReporterPlayerUUID,
				IsReported:      players[i].UUID == report.ReportedPlayerUUID,
				PlayerBanActive: playerBan != nil, UserBanActive: userBan != nil,
				Disabled: players[i].User.IsAdmin || userBan != nil,
			}
			if !participants[i].Disabled {
				actionAvailable = true
			}
		}
		messages := make([]webReportMessage, len(evidence))
		for i := range evidence {
			messages[i] = webReportMessage{ReportEvidenceMessage: evidence[i], PlayerName: reportPlayerName(playerNames, evidence[i].ProfileID)}
		}
		if report.CapturedName.Valid {
			active, err := app.ActiveBan(BanTypeName, report.CapturedName.String)
			if err != nil {
				return err
			}
			if report.Type == ReportTypeUsername {
				actionAvailable = active == nil
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
			Evidence: messages, Participants: participants,
			ReporterName: reportPlayerName(playerNames, report.ReporterPlayerUUID), ReportedName: reportedProfileName(report, playerNames),
			SkinBanActive: skinBanActive, CapeBanActive: capeBanActive, ActionAvailable: actionAvailable,
		})
	})
}

func FrontDismissReport(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		returnURL := getReturnURL(app, c)
		report, err := app.findReportByID(c.Param("id"))
		if err != nil {
			return wrapWebError(returnURL, err)
		}
		if err := app.dismissReport(report, c.Get(CONTEXT_KEY_USER).(*User)); err != nil {
			return wrapWebError(returnURL, err)
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
			return wrapWebError(returnURL, err)
		}
		if err := c.Request().ParseForm(); err != nil {
			return NewWebError(returnURL, Tr("Invalid report action."))
		}
		request := APIReportBanRequest{
			Texture: c.FormValue("texture"),
		}
		for _, rawTarget := range c.Request().Form["banTarget"] {
			if rawTarget == "" {
				continue
			}
			parts := strings.SplitN(rawTarget, ":", 2)
			if len(parts) != 2 {
				return NewWebError(returnURL, Tr("Invalid report ban target."))
			}
			request.Targets = append(request.Targets, APIReportBanTarget{
				Scope: BanType(parts[0]), PlayerUUID: parts[1],
			})
		}
		if report.Type == ReportTypeChat {
			request.ReasonID, request.ReasonMessage, err = webBanReason(c)
			if err != nil {
				return wrapWebError(returnURL, err)
			}
			request.ExpiresAt, _, err = webBanExpiration(c, "duration", false)
			if err != nil {
				return wrapWebError(returnURL, err)
			}
		}
		if _, err := app.actionReport(report, c.Get(CONTEXT_KEY_USER).(*User), request); err != nil {
			return wrapWebError(returnURL, err)
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
			return wrapWebError(returnURL, err)
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
