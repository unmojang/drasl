package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
)

// Wire-format constants matching the vanilla services API.
const (
	friendsUpdateTypeAdd    = "ADD"
	friendsUpdateTypeRemove = "REMOVE"

	toggleEnabled  = "ENABLED"
	toggleDisabled = "DISABLED"

	presenceStatusOnline           = "ONLINE"
	presenceStatusOffline          = "OFFLINE"
	presenceStatusPlayingOffline   = "PLAYING_OFFLINE"
	presenceStatusPlayingRealms    = "PLAYING_REALMS"
	presenceStatusPlayingServer    = "PLAYING_SERVER"
	presenceStatusPlayingHostedSvr = "PLAYING_HOSTED_SERVER"
)

// Presence entries older than this are treated as offline, matching Mojang's
// 10-minute TTL.
const presenceTTL = 10 * time.Minute

type friendDto struct {
	ProfileID string `json:"profileId"`
	Name      string `json:"name"`
}

type friendsListResponse struct {
	Friends          []friendDto `json:"friends"`
	IncomingRequests []friendDto `json:"incomingRequests"`
	OutgoingRequests []friendDto `json:"outgoingRequests"`
	Empty            bool        `json:"empty"`
}

// Mirrors com.mojang.authlib.yggdrasil.response.ErrorResponse.
type servicesErrorResponse struct {
	Path         string         `json:"path"`
	Error        string         `json:"error,omitempty"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// friendsError renders to a 4xx response from one of the friends routes.
// Status -> details.status (UNKNOWN_PROFILE, ALREADY_FRIENDS, ...).
// TopLevelError -> top-level "error" field (e.g. INVALID_JSON).
type friendsError struct {
	HTTPStatus    int
	Status        string
	TopLevelError string
	Message       string
}

func (e *friendsError) Error() string { return e.Message }

func writeFriendsError(c *echo.Context, err *friendsError) error {
	resp := servicesErrorResponse{
		Path:         c.Request().URL.Path,
		Error:        err.TopLevelError,
		ErrorMessage: err.Message,
	}
	if err.Status != "" {
		resp.Details = map[string]any{"status": err.Status}
	}
	return c.JSON(err.HTTPStatus, resp)
}

func unknownProfileError() *friendsError {
	return &friendsError{
		HTTPStatus: http.StatusBadRequest,
		Status:     "UNKNOWN_PROFILE",
		Message:    "Name or profile does not exist",
	}
}

func alreadyFriendsError(targetUUID string) *friendsError {
	return &friendsError{
		HTTPStatus: http.StatusBadRequest,
		Status:     "ALREADY_FRIENDS",
		Message:    "Already friend with " + targetUUID,
	}
}

// Jackson-style errorMessage for invalid PresenceStatus values, matching the
// production services response.
func invalidPresenceStatusMessage(badStatus string) string {
	const enumList = "[PLAYING_OFFLINE, ONLINE, PLAYING_SERVER, PLAYING_REALMS, PLAYING_HOSTED_SERVER, OFFLINE]"
	return "Failed to convert argument [request] for value [null] due to: " +
		"Cannot deserialize value of type `net.minecraft.api.userinteractions.client.PresenceStatus`" +
		" from String \"" + badStatus + "\": not one of the values accepted for Enum class: " +
		enumList +
		"\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 11]" +
		" (through reference chain: net.minecraft.api.userinteractions.client.PresenceUpdateRequest[\"status\"])"
}

type friendActionRequest struct {
	Name       *string `json:"name,omitempty"`
	ProfileID  *string `json:"profileId,omitempty"`
	UpdateType string  `json:"updateType"`
}

type joinInfoUpdate struct {
	// Raw JSON so a numeric value (PLAYING_REALMS) survives decoding;
	// the spec allows string or numeric, and the legacy string-typed
	// field rejected numbers as INVALID_JSON before the handler saw them.
	Value   json.RawMessage `json:"value,omitempty"`
	Invites []string        `json:"invites,omitempty"`
}

// True if the request-side value field was explicitly set to a non-null
// payload (a string, number, or array/object). Empty bytes and "null"
// both count as "not set".
func (j *joinInfoUpdate) hasValue() bool {
	if j == nil {
		return false
	}
	v := bytes.TrimSpace(j.Value)
	return len(v) > 0 && !bytes.Equal(v, []byte("null"))
}

// Normalized string form of joinInfo.value for storage. Strings are
// unquoted; numbers/bools/etc are returned verbatim.
func (j *joinInfoUpdate) valueString() string {
	if !j.hasValue() {
		return ""
	}
	var s string
	if json.Unmarshal(j.Value, &s) == nil {
		return s
	}
	return string(bytes.TrimSpace(j.Value))
}

type presenceRequest struct {
	Status   string          `json:"status"`
	JoinInfo *joinInfoUpdate `json:"joinInfo,omitempty"`
}

type presenceJoinInfo struct {
	Value   string `json:"value"`
	Invited bool   `json:"invited"`
}

type presenceEntry struct {
	ProfileID   string            `json:"profileId"`
	PMID        string            `json:"pmid"`
	Status      string            `json:"status"`
	JoinInfo    *presenceJoinInfo `json:"joinInfo,omitempty"`
	LastUpdated time.Time         `json:"lastUpdated"`
}

type presenceResponse struct {
	Presence []presenceEntry `json:"presence"`
}

type presenceRecord struct {
	Status      string
	Pmid        string   // routing identifier from the access-token JWT
	HasJoinInfo bool     // POST included a non-null joinInfo: host is open to joins
	JoinValue   string   // PLAYING_HOSTED_SERVER session id
	Invites     []string // dashless player UUIDs invited to this hosted session
	LastUpdated time.Time
}

type PresenceStore struct {
	mu sync.RWMutex
	// keyed by Player UUID (dashed)
	entries map[string]presenceRecord
}

func NewPresenceStore() *PresenceStore {
	return &PresenceStore{entries: make(map[string]presenceRecord)}
}

// Tracks the last time a player's friends list changed, for GET /friends ETag
// caching. In-memory; on restart all clients revalidate once and resume 304s.
type FriendsETagStore struct {
	mu      sync.RWMutex
	startup time.Time
	ts      map[string]time.Time
}

func NewFriendsETagStore() *FriendsETagStore {
	return &FriendsETagStore{
		startup: time.Now().UTC(),
		ts:      make(map[string]time.Time),
	}
}

func (s *FriendsETagStore) etag(playerUUID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.ts[playerUUID]
	if !ok {
		t = s.startup
	}
	return t.Format(time.RFC3339Nano)
}

func (s *FriendsETagStore) Touch(playerUUIDs ...string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range playerUUIDs {
		s.ts[u] = now
	}
}

func (s *FriendsETagStore) Forget(playerUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ts, playerUUID)
}

func (p *PresenceStore) Set(playerUUID string, rec presenceRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rec.LastUpdated.IsZero() {
		rec.LastUpdated = time.Now().UTC()
	}
	p.entries[playerUUID] = rec
}

func (p *PresenceStore) Get(playerUUID string) (presenceRecord, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.entries[playerUUID]
	return r, ok
}

func (p *PresenceStore) Clear(playerUUID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, playerUUID)
}

// Counterparties of every friendship row (accepted or pending), for ETag bumps on delete.
func (app *App) friendsToTouchOnDelete(playerUUID string) ([]string, error) {
	rows, err := app.friendshipsFor(playerUUID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		other := r.RecipientUUID
		if r.RecipientUUID == playerUUID {
			other = r.RequesterUUID
		}
		out = append(out, other)
	}
	return out, nil
}

func (app *App) friendshipsFor(playerUUID string) ([]Friendship, error) {
	var rows []Friendship
	err := app.DB.Where("requester_uuid = ? OR recipient_uuid = ?", playerUUID, playerUUID).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (app *App) playerByUUIDOrName(idOrName string) (*Player, error) {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return nil, gorm.ErrRecordNotFound
	}
	uuidStr, err := ParseUUID(idOrName)
	if err == nil {
		var p Player
		if err := app.DB.First(&p, "uuid = ?", uuidStr).Error; err != nil {
			return nil, err
		}
		return &p, nil
	}
	// fall back to name (case-insensitive - column collates nocase)
	var p Player
	if err := app.DB.First(&p, "name = ?", idOrName).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (app *App) buildFriendsList(playerUUID string) (friendsListResponse, error) {
	rows, err := app.friendshipsFor(playerUUID)
	if err != nil {
		return friendsListResponse{}, err
	}

	friendUUIDs := make([]string, 0, len(rows))
	incomingUUIDs := make([]string, 0)
	outgoingUUIDs := make([]string, 0)
	for _, r := range rows {
		other := r.RecipientUUID
		if r.RecipientUUID == playerUUID {
			other = r.RequesterUUID
		}
		switch r.Status {
		case FriendshipAccepted:
			friendUUIDs = append(friendUUIDs, other)
		case FriendshipPending:
			if r.RequesterUUID == playerUUID {
				outgoingUUIDs = append(outgoingUUIDs, other)
			} else {
				incomingUUIDs = append(incomingUUIDs, other)
			}
		}
	}

	toDtos := func(uuids []string) ([]friendDto, error) {
		out := make([]friendDto, 0, len(uuids))
		if len(uuids) == 0 {
			return out, nil
		}
		var players []Player
		if err := app.DB.Where("uuid IN ?", uuids).Find(&players).Error; err != nil {
			return nil, err
		}
		for _, p := range players {
			id, err := UUIDToID(p.UUID)
			if err != nil {
				return nil, err
			}
			out = append(out, friendDto{ProfileID: id, Name: p.Name})
		}
		return out, nil
	}

	friends, err := toDtos(friendUUIDs)
	if err != nil {
		return friendsListResponse{}, err
	}
	incoming, err := toDtos(incomingUUIDs)
	if err != nil {
		return friendsListResponse{}, err
	}
	outgoing, err := toDtos(outgoingUUIDs)
	if err != nil {
		return friendsListResponse{}, err
	}

	return friendsListResponse{
		Friends:          friends,
		IncomingRequests: incoming,
		OutgoingRequests: outgoing,
		Empty:            len(friends) == 0 && len(incoming) == 0 && len(outgoing) == 0,
	}, nil
}

// GET /friends
func ServicesFriendsGet(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		player := c.Get(CONTEXT_KEY_PLAYER).(*Player)
		etag := app.FriendsETagStore.etag(player.UUID)
		c.Response().Header().Set("ETag", etag)
		if c.Request().Header.Get("If-None-Match") == etag {
			return c.NoContent(http.StatusNotModified)
		}
		resp, err := app.buildFriendsList(player.UUID)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, resp)
	}
}

// PUT /friends
func ServicesFriendsPut(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		player := c.Get(CONTEXT_KEY_PLAYER).(*Player)

		var req friendActionRequest
		if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
			return writeFriendsError(c, &friendsError{
				HTTPStatus:    http.StatusBadRequest,
				TopLevelError: "INVALID_JSON",
				Message:       "Failed to convert argument [request] for value [null] due to: " + err.Error(),
			})
		}

		// ProfileID takes precedence per the spec; both absent => UNKNOWN_PROFILE.
		var lookup string
		switch {
		case req.ProfileID != nil && *req.ProfileID != "":
			lookup = *req.ProfileID
		case req.Name != nil && *req.Name != "":
			lookup = *req.Name
		default:
			return writeFriendsError(c, unknownProfileError())
		}
		target, err := app.playerByUUIDOrName(lookup)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return writeFriendsError(c, unknownProfileError())
			}
			return err
		}

		if target.UUID == player.UUID {
			return writeFriendsError(c, &friendsError{
				HTTPStatus: http.StatusBadRequest,
				Status:     "CANNOT_ADD_SELF",
				Message:    "Cannot add yourself as friend",
			})
		}

		var ferr *friendsError
		switch strings.ToUpper(req.UpdateType) {
		case friendsUpdateTypeAdd:
			unlock := app.FriendshipLocks.Lock(player.UUID, target.UUID)
			ferr, err = app.friendsAdd(player, target)
			unlock()
		case friendsUpdateTypeRemove:
			unlock := app.FriendshipLocks.Lock(player.UUID, target.UUID)
			ferr, err = app.friendsRemove(player, target)
			unlock()
		default:
			return writeFriendsError(c, &friendsError{
				HTTPStatus:    http.StatusBadRequest,
				TopLevelError: "INVALID_JSON",
				Message: "Failed to convert argument [request] for value [null] due to: " +
					"Cannot deserialize value of type `net.minecraft.api.userinteractions.client.FriendUpdateType`" +
					" from String \"" + req.UpdateType + "\": not one of the values accepted for Enum class: " +
					"[ADD, REMOVE]" +
					" (through reference chain: net.minecraft.api.userinteractions.client.FriendUpdateRequest[\"updateType\"])",
			})
		}
		if err != nil {
			return err
		}
		if ferr != nil {
			return writeFriendsError(c, ferr)
		}

		resp, err := app.buildFriendsList(player.UUID)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, resp)
	}
}

// Per-pair lock manager that serializes write paths against a given
// (caller, target) pair so two concurrent /friends PUTs in opposite
// directions can't both find "no existing row" and both Create.
type friendshipLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func newFriendshipLocks() *friendshipLocks {
	return &friendshipLocks{m: make(map[string]*sync.Mutex)}
}

func friendshipPairKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

// Lock the pair and return an unlock func.
func (l *friendshipLocks) Lock(a, b string) func() {
	key := friendshipPairKey(a, b)
	l.mu.Lock()
	mx, ok := l.m[key]
	if !ok {
		mx = &sync.Mutex{}
		l.m[key] = mx
	}
	l.mu.Unlock()
	mx.Lock()
	return mx.Unlock
}

// Look up the friendship row between two players in either direction.
func (app *App) findFriendship(a, b string) (*Friendship, error) {
	var fr Friendship
	err := app.DB.Where(
		"(requester_uuid = ? AND recipient_uuid = ?) OR (requester_uuid = ? AND recipient_uuid = ?)",
		a, b, b, a,
	).First(&fr).Error
	if err != nil {
		return nil, err
	}
	return &fr, nil
}

// Open a new friend request, or accept a pending inbound one. The target's
// prefs are only checked when creating a brand-new invite - accepting an
// existing inbound request always works.
func (app *App) friendsAdd(caller, target *Player) (*friendsError, error) {
	existing, err := app.findFriendship(caller.UUID, target.UUID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if existing != nil {
		if existing.Status == FriendshipAccepted || existing.RequesterUUID == caller.UUID {
			return alreadyFriendsError(target.UUID), nil
		}
		existing.Status = FriendshipAccepted
		if err := app.DB.Save(existing).Error; err != nil {
			return nil, err
		}
		app.FriendsETagStore.Touch(caller.UUID, target.UUID)
		return nil, nil
	}

	if !target.FriendsEnabled || !target.AcceptInvitesEnabled {
		return &friendsError{
			HTTPStatus: http.StatusForbidden,
			Status:     "INVITE_REJECTED",
			Message:    "User does not have friends enabled or accept invites",
		}, nil
	}

	if err := app.DB.Create(&Friendship{
		RequesterUUID: caller.UUID,
		RecipientUUID: target.UUID,
		Status:        FriendshipPending,
	}).Error; err != nil {
		return nil, err
	}
	app.FriendsETagStore.Touch(caller.UUID, target.UUID)
	return nil, nil
}

// Delete a friendship, decline an incoming request, or revoke an outgoing one.
func (app *App) friendsRemove(caller, target *Player) (*friendsError, error) {
	existing, err := app.findFriendship(caller.UUID, target.UUID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &friendsError{
			HTTPStatus: http.StatusBadRequest,
			Status:     "NOT_FRIENDS",
			Message:    "Not friend with " + target.UUID + " cannot remove",
		}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := app.DB.Delete(existing).Error; err != nil {
		return nil, err
	}
	app.FriendsETagStore.Touch(caller.UUID, target.UUID)
	return nil, nil
}

// POST /presence
func ServicesPresence(app *App) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		player := c.Get(CONTEXT_KEY_PLAYER).(*Player)

		var req presenceRequest
		if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
			return writeFriendsError(c, &friendsError{
				HTTPStatus:    http.StatusBadRequest,
				TopLevelError: "INVALID_JSON",
				Message:       "Failed to convert argument [request] for value [null] due to: " + err.Error(),
			})
		}

		status := strings.ToUpper(strings.TrimSpace(req.Status))
		switch status {
		case presenceStatusOnline, presenceStatusOffline, presenceStatusPlayingOffline,
			presenceStatusPlayingRealms, presenceStatusPlayingServer, presenceStatusPlayingHostedSvr:
		default:
			return writeFriendsError(c, &friendsError{
				HTTPStatus:    http.StatusBadRequest,
				TopLevelError: "INVALID_JSON",
				Message:       invalidPresenceStatusMessage(req.Status),
			})
		}

		if status == presenceStatusOffline {
			app.PresenceStore.Clear(player.UUID)
		} else {
			client, _ := c.Get(CONTEXT_KEY_CLIENT).(*Client)
			rec := presenceRecord{
				Status:      status,
				LastUpdated: time.Now().UTC(),
			}
			if client != nil {
				rec.Pmid = client.Pmid
			}
			// Each /presence post is authoritative for its joinInfo: a status
			// change clears any prior session id and invite list, so leaving
			// PLAYING_HOSTED_SERVER can't leak stale invites to friends.
			if req.JoinInfo != nil {
				rec.HasJoinInfo = true
				if v := req.JoinInfo.valueString(); v != "" {
					rec.JoinValue = v
				}
				if req.JoinInfo.Invites != nil {
					filtered, err := app.filterInvitesToFriends(player.UUID, req.JoinInfo.Invites)
					if err != nil {
						return err
					}
					rec.Invites = filtered
				}
			}
			app.PresenceStore.Set(player.UUID, rec)
		}

		resp, err := app.friendsPresence(player.UUID)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, resp)
	}
}

// Drop any invite UUIDs that aren't accepted friends of the caller. Accepts
// dashed or dashless input; normalises via ParseUUID before comparing.
func (app *App) filterInvitesToFriends(callerUUID string, invites []string) ([]string, error) {
	if len(invites) == 0 {
		return invites, nil
	}
	rows, err := app.friendshipsFor(callerUUID)
	if err != nil {
		return nil, err
	}
	friends := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if r.Status != FriendshipAccepted {
			continue
		}
		other := r.RecipientUUID
		if r.RecipientUUID == callerUUID {
			other = r.RequesterUUID
		}
		friends[strings.ToLower(other)] = struct{}{}
	}
	out := make([]string, 0, len(invites))
	for _, inv := range invites {
		normalized, err := ParseUUID(inv)
		if err != nil {
			continue
		}
		if _, ok := friends[strings.ToLower(normalized)]; ok {
			out = append(out, inv)
		}
	}
	return out, nil
}

// Presence of the caller's accepted friends.
func (app *App) friendsPresence(callerUUID string) (presenceResponse, error) {
	rows, err := app.friendshipsFor(callerUUID)
	if err != nil {
		return presenceResponse{}, err
	}
	out := presenceResponse{Presence: []presenceEntry{}}
	for _, r := range rows {
		if r.Status != FriendshipAccepted {
			continue
		}
		other := r.RecipientUUID
		if r.RecipientUUID == callerUUID {
			other = r.RequesterUUID
		}
		rec, ok := app.PresenceStore.Get(other)
		if !ok {
			// OFFLINE status clears the entry, so missing == offline.
			continue
		}
		if time.Since(rec.LastUpdated) > presenceTTL {
			// Stale entry from a crashed or unreachable client.
			app.PresenceStore.Clear(other)
			continue
		}
		if rec.Pmid == "" {
			// No pmid recorded (legacy entry or client with a pre-pmid
			// token). Skip rather than emit an unroutable entry.
			continue
		}
		entry := presenceEntry{
			ProfileID:   other,
			PMID:        rec.Pmid,
			Status:      rec.Status,
			LastUpdated: rec.LastUpdated.UTC(),
		}
		// Emit joinInfo whenever the host's POST carried one, regardless of
		// status. The client always sends joinInfo.value = null and supplies
		// only the invite list, so HasJoinInfo is the real signal that the
		// host is hosting and accepting joins (an "ask to join" button on the
		// peer requires presence.joinInfo() != null even with no invites).
		if rec.HasJoinInfo {
			invited := false
			for _, inv := range rec.Invites {
				if invitedUUID, err := ParseUUID(inv); err == nil && invitedUUID == callerUUID {
					invited = true
					break
				}
			}
			joinValue := rec.JoinValue
			if joinValue == "" {
				joinValue = rec.Pmid
			}
			entry.JoinInfo = &presenceJoinInfo{
				Value:   joinValue,
				Invited: invited,
			}
		}
		out.Presence = append(out.Presence, entry)
	}
	return out, nil
}
