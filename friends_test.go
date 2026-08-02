package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
)

const (
	FRIENDS_HOST_USER = "FriendsHost"
	FRIENDS_PEER_USER = "FriendsPeer"
)

func TestFriends(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	config := testConfig()
	ts.Setup(config)
	defer ts.Teardown()

	ts.CreateTestUser(t, ts.App, ts.Server, FRIENDS_HOST_USER)
	ts.CreateTestUser(t, ts.App, ts.Server, FRIENDS_PEER_USER)

	t.Run("Test GET/POST /player/attributes (friendsPreferences)", ts.testPlayerAttributesFriendsPreferences)
	t.Run("Test GET /friends auth", ts.testFriendsGetAuth)
	t.Run("Test PUT /friends INVITE_REJECTED when target prefs are off", ts.testFriendsAddInviteRejected)
	t.Run("Test PUT /friends UNKNOWN_PROFILE", ts.testFriendsAddUnknownProfile)
	t.Run("Test PUT /friends CANNOT_ADD_SELF", ts.testFriendsAddSelf)
	t.Run("Test PUT /friends invalid JSON body", ts.testFriendsPutInvalidJSON)
	t.Run("Test PUT /friends invite, accept, list", ts.testFriendsAddAcceptFlow)
	t.Run("Test PUT /friends duplicate ADD is ALREADY_FRIENDS", ts.testFriendsAddDuplicate)
	t.Run("Test PUT /friends accepts inbound even after sender disables prefs", ts.testFriendsAcceptIgnoresSenderPrefs)
	t.Run("Test PUT /friends REMOVE", ts.testFriendsRemove)
	t.Run("Test PUT /friends NOT_FRIENDS on REMOVE without record", ts.testFriendsRemoveNotFriends)
	t.Run("Test PUT /friends lookup by name is case-insensitive", ts.testFriendsLookupByName)
	t.Run("Test PUT /friends lookup by dashless UUID", ts.testFriendsLookupByDashlessUUID)
	t.Run("Test PUT /friends unknown updateType", ts.testFriendsUnknownUpdateType)
	t.Run("Test POST /presence with invalid status", ts.testPresenceInvalidStatus)
	t.Run("Test POST /presence ONLINE then OFFLINE clears", ts.testPresenceOnlineOffline)
	t.Run("Test POST /presence accepts joinInfo on hosted sessions", ts.testPresenceHostedJoinInfo)
	t.Run("Test POST /presence drops invites for non-friends", ts.testPresenceInvitesNonFriendDropped)
	t.Run("Test GET /friends ETag / If-None-Match", ts.testFriendsETag)
	t.Run("Test POST /presence friend sees presence with pmid", ts.testPresenceFriendSeesIt)
	t.Run("Test POST /presence non-friend does not see presence", ts.testPresenceHiddenFromNonFriend)
	t.Run("Test presence entries past TTL are treated as offline", ts.testPresenceStaleExpires)
	t.Run("Test Player deletion cascades to Friendship rows", ts.testFriendsCascadeOnPlayerDelete)
	t.Run("Test access-token pmid is unguessable and per-token", ts.testPmidFromJWT)
}

// resetFriendshipState wipes the friendships table and resets both test
// players' friend prefs to the freshly-created defaults (both off).
func (ts *TestSuite) resetFriendshipState(t *testing.T) {
	assert.Nil(t, ts.App.DB.Exec("DELETE FROM friendships").Error)
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("1=1").Updates(map[string]any{
		"friends_enabled":        false,
		"accept_invites_enabled": false,
	}).Error)
	// Clear presence so cross-test state doesn't bleed through.
	hostPlayer := ts.getPlayer(t, FRIENDS_HOST_USER)
	peerPlayer := ts.getPlayer(t, FRIENDS_PEER_USER)
	ts.App.PresenceStore.Clear(hostPlayer.UUID)
	ts.App.PresenceStore.Clear(peerPlayer.UUID)
}

func (ts *TestSuite) getPlayer(t *testing.T, name string) *Player {
	var p Player
	assert.Nil(t, ts.App.DB.First(&p, "name = ?", name).Error)
	return &p
}

func (ts *TestSuite) enablePrefs(t *testing.T, playerName string) {
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("name = ?", playerName).Updates(map[string]any{
		"friends_enabled":        true,
		"accept_invites_enabled": true,
	}).Error)
}

func (ts *TestSuite) testPlayerAttributesFriendsPreferences(t *testing.T) {
	ts.resetFriendshipState(t)
	token := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken

	{
		rec := ts.Get(t, ts.Server, "/player/attributes", nil, &token)
		assert.Equal(t, http.StatusOK, rec.Code)
		var resp playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, toggleDisabled, resp.FriendsPreferences.Friends)
		assert.Equal(t, toggleDisabled, resp.FriendsPreferences.AcceptInvites)
	}

	{
		payload := playerAttributesUpdateRequest{
			FriendsPreferences: &playerAttributesFriendsPreferences{
				Friends:       toggleEnabled,
				AcceptInvites: toggleEnabled,
			},
		}
		rec := ts.PostJSON(t, ts.Server, "/player/attributes", payload, nil, &token)
		assert.Equal(t, http.StatusOK, rec.Code)
		var resp playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, toggleEnabled, resp.FriendsPreferences.Friends)
		assert.Equal(t, toggleEnabled, resp.FriendsPreferences.AcceptInvites)

		// And it persists.
		p := ts.getPlayer(t, FRIENDS_HOST_USER)
		assert.True(t, p.FriendsEnabled)
		assert.True(t, p.AcceptInvitesEnabled)
	}
}

func (ts *TestSuite) testFriendsGetAuth(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/friends", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func (ts *TestSuite) testFriendsAddInviteRejected(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	body := friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeAdd}
	rec := ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVITE_REJECTED", resp.Details["status"])
}

func (ts *TestSuite) testFriendsAddUnknownProfile(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken

	body := friendActionRequest{Name: Ptr("nonExistentPlayer"), UpdateType: friendsUpdateTypeAdd}
	rec := ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "UNKNOWN_PROFILE", resp.Details["status"])
}

func (ts *TestSuite) testFriendsAddSelf(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	host := ts.getPlayer(t, FRIENDS_HOST_USER)

	body := friendActionRequest{ProfileID: &host.UUID, UpdateType: friendsUpdateTypeAdd}
	rec := ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CANNOT_ADD_SELF", resp.Details["status"])
	assert.Equal(t, "Cannot add yourself as friend", resp.ErrorMessage)
}

func (ts *TestSuite) testFriendsPutInvalidJSON(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken

	// Send raw bad JSON (bypassing json.Marshal in PutJSON).
	req := httptest.NewRequest(http.MethodPut, "/friends", strings.NewReader("not-json"))
	req.Header.Add("Authorization", "Bearer "+hostToken)
	req.Header.Add("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVALID_JSON", resp.Error)
}

func (ts *TestSuite) testFriendsAddAcceptFlow(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peerToken := ts.authenticate(t, FRIENDS_PEER_USER, TEST_PASSWORD).AccessToken

	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	// 1. Host sends invite to peer.
	addBody := friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeAdd}
	rec := ts.PutJSON(t, ts.Server, "/friends", addBody, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// 2. Host's friends list shows the outgoing request, peer's shows incoming.
	rec = ts.Get(t, ts.Server, "/friends", nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var hostList friendsListResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&hostList))
	assert.Equal(t, 1, len(hostList.OutgoingRequests))
	assert.Equal(t, Unwrap(UUIDToID(peer.UUID)), hostList.OutgoingRequests[0].ProfileID)
	assert.Equal(t, peer.Name, hostList.OutgoingRequests[0].Name)
	assert.Equal(t, 0, len(hostList.Friends))
	assert.False(t, hostList.Empty)

	rec = ts.Get(t, ts.Server, "/friends", nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var peerList friendsListResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&peerList))
	assert.Equal(t, 1, len(peerList.IncomingRequests))
	assert.Equal(t, Unwrap(UUIDToID(host.UUID)), peerList.IncomingRequests[0].ProfileID)

	// 3. Peer accepts by sending ADD back.
	acceptBody := friendActionRequest{ProfileID: &host.UUID, UpdateType: friendsUpdateTypeAdd}
	rec = ts.PutJSON(t, ts.Server, "/friends", acceptBody, nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// 4. Both sides now see each other as friends.
	rec = ts.Get(t, ts.Server, "/friends", nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&hostList))
	assert.Equal(t, 1, len(hostList.Friends))
	assert.Equal(t, Unwrap(UUIDToID(peer.UUID)), hostList.Friends[0].ProfileID)
	assert.Equal(t, 0, len(hostList.OutgoingRequests))
}

func (ts *TestSuite) testFriendsAddDuplicate(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	body := friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeAdd}
	rec := ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Re-sending should fail.
	rec = ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ALREADY_FRIENDS", resp.Details["status"])
	assert.Equal(t, "Already friend with "+peer.UUID, resp.ErrorMessage)
	assert.Equal(t, "/friends", resp.Path)
}

// testFriendsAcceptIgnoresSenderPrefs verifies that turning off the sender's
// prefs after they sent the invite does not prevent the recipient from
// accepting it. See friendsAdd's "no existing friendship" branch.
func (ts *TestSuite) testFriendsAcceptIgnoresSenderPrefs(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_HOST_USER)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peerToken := ts.authenticate(t, FRIENDS_PEER_USER, TEST_PASSWORD).AccessToken

	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	// Host invites peer.
	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeAdd}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Host disables their own prefs.
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", host.UUID).Updates(map[string]any{
		"friends_enabled":        false,
		"accept_invites_enabled": false,
	}).Error)

	// Peer accepts - must still succeed because there's already a pending row.
	rec = ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &host.UUID, UpdateType: friendsUpdateTypeAdd}, nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Friendship is accepted.
	var fr Friendship
	assert.Nil(t, ts.App.DB.First(&fr, "requester_uuid = ? AND recipient_uuid = ?", host.UUID, peer.UUID).Error)
	assert.Equal(t, FriendshipAccepted, fr.Status)
}

func (ts *TestSuite) testFriendsRemove(t *testing.T) {
	ts.resetFriendshipState(t)
	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)
	assert.Nil(t, ts.App.DB.Create(&Friendship{
		RequesterUUID: host.UUID,
		RecipientUUID: peer.UUID,
		Status:        FriendshipAccepted,
	}).Error)

	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeRemove}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	var count int64
	assert.Nil(t, ts.App.DB.Model(&Friendship{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func (ts *TestSuite) testFriendsRemoveNotFriends(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeRemove}, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "NOT_FRIENDS", resp.Details["status"])
	assert.Equal(t, "Not friend with "+peer.UUID+" cannot remove", resp.ErrorMessage)
	assert.Equal(t, "/friends", resp.Path)
}

func (ts *TestSuite) testFriendsLookupByName(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken

	// Use lowercased name to confirm case-insensitive matching.
	lowered := "friendspeer"
	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{Name: &lowered, UpdateType: friendsUpdateTypeAdd}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testFriendsLookupByDashlessUUID(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	dashless := Unwrap(UUIDToID(peer.UUID))
	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &dashless, UpdateType: friendsUpdateTypeAdd}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testFriendsUnknownUpdateType(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	rec := ts.PutJSON(t, ts.Server, "/friends",
		friendActionRequest{ProfileID: &peer.UUID, UpdateType: "TOGGLE"}, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVALID_JSON", resp.Error)
	assert.Contains(t, resp.ErrorMessage, "FriendUpdateType")
	assert.Contains(t, resp.ErrorMessage, "[ADD, REMOVE]")
}

func (ts *TestSuite) testPresenceInvalidStatus(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken

	rec := ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: "AWAY"}, nil, &hostToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp servicesErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVALID_JSON", resp.Error)
	assert.Contains(t, resp.ErrorMessage, "PresenceStatus")
	assert.Contains(t, resp.ErrorMessage, "AWAY")
	assert.Contains(t, resp.ErrorMessage, "PLAYING_HOSTED_SERVER")
}

func (ts *TestSuite) testPresenceOnlineOffline(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	host := ts.getPlayer(t, FRIENDS_HOST_USER)

	rec := ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOnline}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	_, ok := ts.App.PresenceStore.Get(host.UUID)
	assert.True(t, ok)

	rec = ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOffline}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	_, ok = ts.App.PresenceStore.Get(host.UUID)
	assert.False(t, ok)
}

func (ts *TestSuite) testPresenceHostedJoinInfo(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)
	assert.Nil(t, ts.App.DB.Create(&Friendship{
		RequesterUUID: host.UUID,
		RecipientUUID: peer.UUID,
		Status:        FriendshipAccepted,
	}).Error)

	// Value + invites are both accepted (clients with the "limited" privacy
	// setting report ONLINE but still send joinInfo for hosted worlds).
	dashlessPeer := Unwrap(UUIDToID(peer.UUID))
	rec := ts.PostJSON(t, ts.Server, "/presence", presenceRequest{
		Status: presenceStatusPlayingHostedSvr,
		JoinInfo: &joinInfoUpdate{
			Value:   json.RawMessage(`"session-id-42"`),
			Invites: []string{dashlessPeer},
		},
	}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	stored, _ := ts.App.PresenceStore.Get(host.UUID)
	assert.Equal(t, "session-id-42", stored.JoinValue)
	assert.Equal(t, []string{dashlessPeer}, stored.Invites)
}

func (ts *TestSuite) testPresenceInvitesNonFriendDropped(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	// Peer is not a friend of host. Inviting them must be silently dropped.
	dashlessPeer := Unwrap(UUIDToID(peer.UUID))
	rec := ts.PostJSON(t, ts.Server, "/presence", presenceRequest{
		Status:   presenceStatusPlayingHostedSvr,
		JoinInfo: &joinInfoUpdate{Invites: []string{dashlessPeer}},
	}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	stored, _ := ts.App.PresenceStore.Get(host.UUID)
	assert.Equal(t, []string{}, stored.Invites)
}

func (ts *TestSuite) testPresenceFriendSeesIt(t *testing.T) {
	ts.resetFriendshipState(t)
	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)
	assert.Nil(t, ts.App.DB.Create(&Friendship{
		RequesterUUID: host.UUID,
		RecipientUUID: peer.UUID,
		Status:        FriendshipAccepted,
	}).Error)

	// Host publishes a hosted-server session that invites peer. joinInfo.value
	// is rejected by /presence, so seed it directly in the store - but reuse a
	// real access token's pmid so the response carries a routable value.
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	hostClient, err := ts.App.GetClient(hostToken, mo.None[string](), StalePolicyAllow, true)
	assert.Nil(t, err)
	dashlessPeer := Unwrap(UUIDToID(peer.UUID))
	ts.App.PresenceStore.Set(host.UUID, presenceRecord{
		Status:      presenceStatusPlayingHostedSvr,
		Pmid:        hostClient.Pmid,
		HasJoinInfo: true,
		JoinValue:   "host-session",
		Invites:     []string{dashlessPeer},
	})

	// Peer publishes ONLINE and inspects the returned presence list.
	peerToken := ts.authenticate(t, FRIENDS_PEER_USER, TEST_PASSWORD).AccessToken
	rec := ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOnline}, nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp presenceResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 1, len(resp.Presence))
	entry := resp.Presence[0]
	assert.Equal(t, host.UUID, entry.ProfileID)
	assert.Equal(t, hostClient.Pmid, entry.PMID)
	assert.Equal(t, presenceStatusPlayingHostedSvr, entry.Status)
	if assert.NotNil(t, entry.JoinInfo) {
		assert.Equal(t, "host-session", entry.JoinInfo.Value)
		assert.True(t, entry.JoinInfo.Invited)
	}
	assert.False(t, entry.LastUpdated.IsZero())
}

func (ts *TestSuite) testPresenceHiddenFromNonFriend(t *testing.T) {
	ts.resetFriendshipState(t)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	rec := ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOnline}, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	peerToken := ts.authenticate(t, FRIENDS_PEER_USER, TEST_PASSWORD).AccessToken
	rec = ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOnline}, nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp presenceResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, len(resp.Presence))
}

func (ts *TestSuite) testPresenceStaleExpires(t *testing.T) {
	ts.resetFriendshipState(t)
	host := ts.getPlayer(t, FRIENDS_HOST_USER)
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)
	assert.Nil(t, ts.App.DB.Create(&Friendship{
		RequesterUUID: host.UUID,
		RecipientUUID: peer.UUID,
		Status:        FriendshipAccepted,
	}).Error)

	// Backdate the host's presence past the TTL.
	ts.App.PresenceStore.Set(host.UUID, presenceRecord{
		Status:      presenceStatusOnline,
		LastUpdated: time.Now().Add(-2 * presenceTTL),
	})

	peerToken := ts.authenticate(t, FRIENDS_PEER_USER, TEST_PASSWORD).AccessToken
	rec := ts.PostJSON(t, ts.Server, "/presence",
		presenceRequest{Status: presenceStatusOnline}, nil, &peerToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp presenceResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, len(resp.Presence))

	// Stale entry should have been cleared.
	_, ok := ts.App.PresenceStore.Get(host.UUID)
	assert.False(t, ok)
}

func (ts *TestSuite) testFriendsETag(t *testing.T) {
	ts.resetFriendshipState(t)
	ts.enablePrefs(t, FRIENDS_PEER_USER)
	hostToken := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)

	// Initial GET returns 200 with an ETag.
	rec := ts.Get(t, ts.Server, "/friends", nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	etag1 := rec.Header().Get("ETag")
	assert.NotEmpty(t, etag1)

	// Re-GET with matching If-None-Match returns 304 with empty body.
	req := httptest.NewRequest(http.MethodGet, "/friends", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	req.Header.Set("If-None-Match", etag1)
	rec = httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotModified, rec.Code)
	assert.Equal(t, etag1, rec.Header().Get("ETag"))
	assert.Equal(t, 0, rec.Body.Len())

	// Sending an invite bumps the ETag on the next GET.
	body := friendActionRequest{ProfileID: &peer.UUID, UpdateType: friendsUpdateTypeAdd}
	rec = ts.PutJSON(t, ts.Server, "/friends", body, nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	rec = ts.Get(t, ts.Server, "/friends", nil, &hostToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	etag2 := rec.Header().Get("ETag")
	assert.NotEqual(t, etag1, etag2)

	// Stale If-None-Match revalidates with 200 and the new ETag.
	req = httptest.NewRequest(http.MethodGet, "/friends", nil)
	req.Header.Set("Authorization", "Bearer "+hostToken)
	req.Header.Set("If-None-Match", etag1)
	rec = httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, etag2, rec.Header().Get("ETag"))
}

func (ts *TestSuite) testFriendsCascadeOnPlayerDelete(t *testing.T) {
	ts.resetFriendshipState(t)
	// Create a throwaway player to delete so we don't disturb the shared
	// FRIENDS_HOST/PEER players used by other subtests.
	user, err := ts.App.CreateUser(
		&GOD,
		"FriendsCascade",
		Ptr(TEST_PASSWORD),
		PotentiallyInsecure[[]OIDCIdentitySpec]{Value: []OIDCIdentitySpec{}},
		false, false,
		nil, nil, nil, nil,
		false,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	assert.Nil(t, err)
	throwaway := user.Players[0]
	peer := ts.getPlayer(t, FRIENDS_PEER_USER)
	assert.Nil(t, ts.App.DB.Create(&Friendship{
		RequesterUUID: throwaway.UUID,
		RecipientUUID: peer.UUID,
		Status:        FriendshipAccepted,
	}).Error)

	assert.Nil(t, ts.App.DB.Delete(&throwaway).Error)

	var count int64
	assert.Nil(t, ts.App.DB.Model(&Friendship{}).Where("requester_uuid = ? OR recipient_uuid = ?", throwaway.UUID, throwaway.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func (ts *TestSuite) testPmidFromJWT(t *testing.T) {
	// Two access tokens for the same player should carry distinct pmids (no
	// deterministic derivation from the player UUID).
	a := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	b := ts.authenticate(t, FRIENDS_HOST_USER, TEST_PASSWORD).AccessToken
	ca, err := ts.App.GetClient(a, mo.None[string](), StalePolicyAllow, true)
	assert.Nil(t, err)
	cb, err := ts.App.GetClient(b, mo.None[string](), StalePolicyAllow, true)
	assert.Nil(t, err)
	assert.NotEqual(t, "", ca.Pmid)
	assert.NotEqual(t, "", cb.Pmid)
	assert.NotEqual(t, ca.Pmid, cb.Pmid)
}
