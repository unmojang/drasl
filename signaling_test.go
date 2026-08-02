package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/websocket"
)

const (
	SIGNALING_USER_A = "SignalingAlice"
	SIGNALING_USER_B = "SignalingBob"
)

func TestSignalingWSBaseURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		base, root, want string
	}{
		{"http://localhost:25585", "/signaling", "ws://localhost:25585/signaling"},
		{"https://drasl.example.com", "/authlib-injector/signaling", "wss://drasl.example.com/authlib-injector/signaling"},
		{"http://drasl.example.com/", "/signaling", "ws://drasl.example.com/signaling"},
		{"https://drasl.example.com/prefix", "/signaling", "wss://drasl.example.com/prefix/signaling"},
	}
	for _, c := range cases {
		got, err := signalingWSBaseURL(c.base, c.root)
		assert.Nil(t, err, c.base)
		assert.Equal(t, c.want, got)
	}
}

func TestTurnAuthServersExternal(t *testing.T) {
	t.Parallel()
	app := &App{Config: &Config{ExternalTURNServers: []TURNServerConfig{{
		Username: "u", Password: "p",
		Urls: []string{"turn:turn.example.org:3478"},
	}}}}
	servers := app.turnAuthServers("11111111-2222-3333-4444-555555555555")
	assert.Equal(t, 1, len(servers))
	assert.Equal(t, "u", servers[0].Username)
	assert.Equal(t, "p", servers[0].Password)
	assert.Equal(t, []string{"turn:turn.example.org:3478"}, servers[0].Urls)
}

func TestTurnAuthServersNone(t *testing.T) {
	t.Parallel()
	// No external configured and no embedded TURN running -> nil.
	app := &App{Config: &Config{}}
	assert.Nil(t, app.turnAuthServers("11111111-2222-3333-4444-555555555555"))
}

func TestSignalingHubRegisterLookup(t *testing.T) {
	t.Parallel()
	hub := NewSignalingHub()
	s := &signalingSession{hub: hub, pmid: "abc"}
	assert.Empty(t, hub.register(s))
	assert.Equal(t, s, hub.lookup("abc"))

	// A second register returns the previous session.
	s2 := &signalingSession{hub: hub, pmid: "abc"}
	replaced := hub.register(s2)
	assert.Equal(t, []*signalingSession{s}, replaced)
	assert.Equal(t, s2, hub.lookup("abc"))

	// Unregister of a different (already-replaced) session is a no-op for
	// the current entry.
	hub.unregister(s)
	assert.Equal(t, s2, hub.lookup("abc"))

	hub.unregister(s2)
	assert.Nil(t, hub.lookup("abc"))
}

func TestSignalingHubEvictsSamePlayerDifferentPmid(t *testing.T) {
	t.Parallel()
	hub := NewSignalingHub()
	old := &signalingSession{hub: hub, pmid: "pmid-old", playerUUID: "player-1"}
	assert.Empty(t, hub.register(old))

	// Same player, fresh pmid (as would happen after token refresh).
	new := &signalingSession{hub: hub, pmid: "pmid-new", playerUUID: "player-1"}
	replaced := hub.register(new)
	assert.Equal(t, []*signalingSession{old}, replaced)
	assert.Equal(t, new, hub.lookup("pmid-new"))
	// Old session still in the map until caller closes it; that's fine -
	// the caller is contracted to do so outside the hub lock.
}

func TestSignalingHubClosePlayer(t *testing.T) {
	t.Parallel()
	hub := NewSignalingHub()
	// Two sessions for the same player, plus one for an unrelated player.
	// signalingSession.close() is nil-safe on conn, so we can drive
	// closePlayer directly without standing up real WebSocket conns.
	s1 := &signalingSession{hub: hub, pmid: "a", playerUUID: "victim"}
	s2 := &signalingSession{hub: hub, pmid: "b", playerUUID: "victim"}
	bystander := &signalingSession{hub: hub, pmid: "c", playerUUID: "other"}
	hub.sessions[s1.pmid] = s1
	hub.sessions[s2.pmid] = s2
	hub.sessions[bystander.pmid] = bystander

	hub.closePlayer("victim")
	assert.Nil(t, hub.lookup("a"))
	assert.Nil(t, hub.lookup("b"))
	assert.Equal(t, bystander, hub.lookup("c"))
}

// signalingTestEnv spins up a TestSuite plus an httptest.Server fronting its
// Echo handler so we can dial real WebSocket connections.
type signalingTestEnv struct {
	ts   *TestSuite
	http *httptest.Server
	host string // host:port for ws:// URLs
}

func setupSignalingEnv(t *testing.T) *signalingTestEnv {
	ts := &TestSuite{}
	ts.Setup(testConfig())
	ts.CreateTestUser(t, ts.App, ts.Server, SIGNALING_USER_A)
	ts.CreateTestUser(t, ts.App, ts.Server, SIGNALING_USER_B)

	srv := httptest.NewServer(ts.Server)
	u, err := url.Parse(srv.URL)
	assert.Nil(t, err)
	return &signalingTestEnv{ts: ts, http: srv, host: u.Host}
}

func (e *signalingTestEnv) teardown() {
	e.http.Close()
	e.ts.Teardown()
}

func (e *signalingTestEnv) accessTokenFor(t *testing.T, username string) string {
	return e.ts.authenticate(t, username, TEST_PASSWORD).AccessToken
}

func (e *signalingTestEnv) pmidFor(t *testing.T, token string) string {
	client, err := e.ts.App.GetClient(token, mo.None[string](), StalePolicyAllow, true)
	assert.Nil(t, err)
	return client.Pmid
}

// Establish accepted friendship between two users so the friendship gate on
// signaling SendClientMessage doesn't reject relay tests.
func (e *signalingTestEnv) befriend(t *testing.T, a, b string) {
	var pa, pb Player
	assert.Nil(t, e.ts.App.DB.First(&pa, "name = ?", a).Error)
	assert.Nil(t, e.ts.App.DB.First(&pb, "name = ?", b).Error)
	assert.Nil(t, e.ts.App.DB.Where(
		"(requester_uuid = ? AND recipient_uuid = ?) OR (requester_uuid = ? AND recipient_uuid = ?)",
		pa.UUID, pb.UUID, pb.UUID, pa.UUID,
	).Delete(&Friendship{}).Error)
	assert.Nil(t, e.ts.App.DB.Create(&Friendship{
		RequesterUUID: pa.UUID,
		RecipientUUID: pb.UUID,
		Status:        FriendshipAccepted,
	}).Error)
}

func TestSignalingConfigurationHandler(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}
	ts.Setup(testConfig())
	defer ts.Teardown()
	ts.CreateTestUser(t, ts.App, ts.Server, SIGNALING_USER_A)

	{
		// No x-mojangauth header -> 401.
		req := httptest.NewRequest(http.MethodGet, "/signaling/api/v1.0/configuration/java", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	token := ts.authenticate(t, SIGNALING_USER_A, TEST_PASSWORD).AccessToken

	{
		req := httptest.NewRequest(http.MethodGet, "/signaling/api/v1.0/configuration/java", nil)
		req.Header.Set(signalingHeaderAuth, token)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var resp struct {
			Result struct {
				SignalingURI  string `json:"signalingUri"`
				PingFrequency string `json:"pingFrequency"`
			} `json:"result"`
		}
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
		u, err := url.Parse(resp.Result.SignalingURI)
		assert.Nil(t, err)
		// BaseURL in testConfig is https://drasl.example.com, so we expect wss.
		assert.Equal(t, "wss", u.Scheme)
		assert.Equal(t, "/signaling", u.Path)
		assert.Equal(t, "00:01:00", resp.Result.PingFrequency)
	}

	{
		// authlib-injector mount also resolves.
		req := httptest.NewRequest(http.MethodGet, "/authlib-injector/signaling/api/v1.0/configuration/java", nil)
		req.Header.Set(signalingHeaderAuth, token)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		var resp struct {
			Result struct {
				SignalingURI  string `json:"signalingUri"`
				PingFrequency string `json:"pingFrequency"`
			} `json:"result"`
		}
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&resp))
		u, err := url.Parse(resp.Result.SignalingURI)
		assert.Nil(t, err)
		assert.Equal(t, "/authlib-injector/signaling", u.Path)
		assert.Equal(t, "00:01:00", resp.Result.PingFrequency)
	}
}

// dialSignaling opens a WebSocket connection to the test signaling server
// with the given x-mojangauth token.
func dialSignaling(t *testing.T, env *signalingTestEnv, token string) *websocket.Conn {
	wsURL := "ws://" + env.host + "/authlib-injector/signaling" + signalingWSPath
	cfg, err := websocket.NewConfig(wsURL, "http://"+env.host)
	assert.Nil(t, err)
	cfg.Header.Set(signalingHeaderAuth, token)
	conn, err := websocket.DialConfig(cfg)
	assert.Nil(t, err)
	return conn
}

// readEnvelope reads a single RPC envelope frame with a deadline.
func readEnvelope(t *testing.T, conn *websocket.Conn) rpcEnvelope {
	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	var env rpcEnvelope
	buf := make([]byte, signalingMaxMessageBytes)
	n, err := conn.Read(buf)
	assert.Nil(t, err)
	assert.Nil(t, json.Unmarshal(buf[:n], &env))
	return env
}

func writeEnvelope(t *testing.T, conn *websocket.Conn, env rpcEnvelope) {
	payload, err := json.Marshal(env)
	assert.Nil(t, err)
	_, err = conn.Write(payload)
	assert.Nil(t, err)
}

func TestSignalingPing(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	conn := dialSignaling(t, env, env.accessTokenFor(t, SIGNALING_USER_A))
	defer conn.Close()

	writeEnvelope(t, conn, rpcEnvelope{JSONRPC: "2.0", Method: signalingMethodPing})
	env2 := readEnvelope(t, conn)
	assert.Equal(t, signalingMethodPong, env2.Method)
	assert.Equal(t, "2.0", env2.JSONRPC)
}

func TestSignalingTurnAuth(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	conn := dialSignaling(t, env, env.accessTokenFor(t, SIGNALING_USER_A))
	defer conn.Close()

	writeEnvelope(t, conn, rpcEnvelope{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  signalingMethodTurnAuth,
	})
	env2 := readEnvelope(t, conn)
	assert.Equal(t, json.RawMessage(`1`), env2.ID)
	assert.Nil(t, env2.Error)
	var result turnAuthResult
	assert.Nil(t, json.Unmarshal(env2.Result, &result))
	assert.Equal(t, int64(signalingTurnTTL.Seconds()), result.ExpirationInSeconds)
	assert.True(t, len(result.TurnAuthServers) >= 1)
}

func TestSignalingSendUnknownPeer(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	conn := dialSignaling(t, env, env.accessTokenFor(t, SIGNALING_USER_A))
	defer conn.Close()

	// Make up a pmid that maps to nobody connected.
	unknownPmid := "00000000-0000-0000-0000-000000000099"
	params, err := json.Marshal([]any{nil, unknownPmid, "{}"})
	assert.Nil(t, err)
	writeEnvelope(t, conn, rpcEnvelope{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`42`),
		Method:  signalingMethodSendClientMsg,
		Params:  params,
	})
	env2 := readEnvelope(t, conn)
	if assert.NotNil(t, env2.Error) {
		assert.Equal(t, signalingErrServiceCode, env2.Error.Code)
		// Encoded as the SignalingErrorMapper-friendly shape.
		dataBytes, _ := json.Marshal(env2.Error.Data)
		assert.Contains(t, string(dataBytes), signalingErrDataUnknownPlayer)
	}
}

func TestSignalingRelaysToPeer(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	env.befriend(t, SIGNALING_USER_A, SIGNALING_USER_B)

	aliceToken := env.accessTokenFor(t, SIGNALING_USER_A)
	bobToken := env.accessTokenFor(t, SIGNALING_USER_B)
	alice := dialSignaling(t, env, aliceToken)
	defer alice.Close()
	bob := dialSignaling(t, env, bobToken)
	defer bob.Close()

	alicePmid := env.pmidFor(t, aliceToken)
	bobPmid := env.pmidFor(t, bobToken)

	// Bob is registered after the WS handler has run; the dial returns once
	// the upgrade completes, but registration happens async. Allow a brief
	// wait for the handler to register the session in the hub.
	waitForSession(t, env.ts.App.SignalingHub, bobPmid)

	encoded := `{"type":"JOIN_REQUEST","sessionId":"abc"}`
	params, err := json.Marshal([]any{nil, bobPmid, encoded})
	assert.Nil(t, err)
	writeEnvelope(t, alice, rpcEnvelope{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`7`),
		Method:  signalingMethodSendClientMsg,
		Params:  params,
	})

	// Bob receives the relayed notification.
	got := readEnvelope(t, bob)
	assert.Equal(t, signalingMethodReceiveMessage, got.Method)
	var arr []receivedClientMessage
	assert.Nil(t, json.Unmarshal(got.Params, &arr))
	if assert.Equal(t, 1, len(arr)) {
		assert.Equal(t, alicePmid, arr[0].From)
		assert.Equal(t, encoded, arr[0].Message)
	}

	// Alice gets a success ack for her request.
	ack := readEnvelope(t, alice)
	assert.Equal(t, json.RawMessage(`7`), ack.ID)
	assert.Nil(t, ack.Error)
}

func TestSignalingReplacesPreviousSession(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	token := env.accessTokenFor(t, SIGNALING_USER_A)
	alicePmid := env.pmidFor(t, token)
	first := dialSignaling(t, env, token)
	defer first.Close()

	waitForSession(t, env.ts.App.SignalingHub, alicePmid)

	second := dialSignaling(t, env, token)
	defer second.Close()
	waitForSession(t, env.ts.App.SignalingHub, alicePmid)

	// First connection should now be closed by the server.
	assert.Nil(t, first.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1024)
	_, err := first.Read(buf)
	assert.NotNil(t, err) // EOF or use-of-closed-network-connection
}

func TestSignalingNonFriendDropped(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	// Alice and Bob are connected but not friends. Alice's relay attempt to
	// Bob must look indistinguishable from "Player unreachable".
	aliceToken := env.accessTokenFor(t, SIGNALING_USER_A)
	bobToken := env.accessTokenFor(t, SIGNALING_USER_B)
	alice := dialSignaling(t, env, aliceToken)
	defer alice.Close()
	bob := dialSignaling(t, env, bobToken)
	defer bob.Close()
	bobPmid := env.pmidFor(t, bobToken)
	waitForSession(t, env.ts.App.SignalingHub, bobPmid)

	params, err := json.Marshal([]any{nil, bobPmid, "{}"})
	assert.Nil(t, err)
	writeEnvelope(t, alice, rpcEnvelope{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`9`),
		Method:  signalingMethodSendClientMsg,
		Params:  params,
	})
	got := readEnvelope(t, alice)
	if assert.NotNil(t, got.Error) {
		assert.Equal(t, signalingErrServiceCode, got.Error.Code)
	}
}

func TestSignalingEvictsOnTokenRefresh(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	// Two independent access tokens for the same player carry distinct pmids;
	// the new WS connection must retire the old session under the old pmid so
	// /presence doesn't advertise an unreachable pmid to friends.
	tokenA := env.accessTokenFor(t, SIGNALING_USER_A)
	tokenB := env.accessTokenFor(t, SIGNALING_USER_A)
	pmidA := env.pmidFor(t, tokenA)
	pmidB := env.pmidFor(t, tokenB)
	assert.NotEqual(t, pmidA, pmidB)

	first := dialSignaling(t, env, tokenA)
	defer first.Close()
	waitForSession(t, env.ts.App.SignalingHub, pmidA)

	second := dialSignaling(t, env, tokenB)
	defer second.Close()
	waitForSession(t, env.ts.App.SignalingHub, pmidB)

	// Old session under the stale pmid should be evicted and its conn closed.
	assert.Nil(t, first.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 1024)
	_, err := first.Read(buf)
	assert.NotNil(t, err)
	waitForNoSession(t, env.ts.App.SignalingHub, pmidA)
}

func TestSignalingUnauthenticatedDial(t *testing.T) {
	t.Parallel()
	env := setupSignalingEnv(t)
	defer env.teardown()

	wsURL := "ws://" + env.host + "/authlib-injector/signaling" + signalingWSPath
	cfg, err := websocket.NewConfig(wsURL, "http://"+env.host)
	assert.Nil(t, err)
	_, err = websocket.DialConfig(cfg)
	assert.NotNil(t, err)
	// The server returns a 401 JSON body and never upgrades to WebSocket.
	assert.True(t, strings.Contains(err.Error(), "bad status") ||
		strings.Contains(err.Error(), "401"))
}

// waitForSession blocks until the hub has a session for the given pmid or 2s
// have passed.
func waitForSession(t *testing.T, hub *SignalingHub, pmid string) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.lookup(pmid) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session for pmid %s never registered", pmid)
}

func waitForNoSession(t *testing.T, hub *SignalingHub, pmid string) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.lookup(pmid) == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session for pmid %s never unregistered", pmid)
}
