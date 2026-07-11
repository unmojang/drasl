package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
	"github.com/samber/mo"
	"golang.org/x/net/websocket"
)

// JSON-RPC 2.0 signaling between Minecraft P2P peers. See
// net.minecraft.client.multiplayer.p2p.* in the vanilla 26.2 client.
// Routing key is the per-token pmid carried as a JWT claim in the access
// token; only friends learn it (via /presence), so non-friends can't address
// the signaling mailbox.

const (
	signalingMethodPing           = "System_Ping_v1_0"
	signalingMethodPong           = "System_Pong_v1_0"
	signalingMethodTurnAuth       = "Signaling_TurnAuth_v1_0"
	signalingMethodSendClientMsg  = "Signaling_SendClientMessage_v1_0"
	signalingMethodReceiveMessage = "Signaling_ReceiveMessage_v1_0"
	signalingHeaderAuth           = "x-mojangauth"
	signalingWSPath               = "/ws/v1.0/messaging/connect/java"
	signalingConfigPath           = "/api/v1.0/configuration/java"
	signalingMaxMessageBytes      = 65536
	signalingErrServiceCode       = -32000
	signalingErrDataUnknownPlayer = "UnknownPlayer"
)

// TURN credential validation window. Baked into the HMAC username as the
// <unix-expiry> half, and echoed to the client as ExpirationInSeconds so it
// knows when to request a fresh pair via Signaling_TurnAuth_v1_0. Unrelated
// to TURN allocation lifetime, which is negotiated via the STUN LIFETIME
// attribute and capped by the TURN server.
const signalingTurnTTL = 7 * 24 * time.Hour

// Bound on a single sendJSON. A misbehaving (or merely slow) peer must not be
// able to indefinitely block other peers that are trying to relay messages
// to it via target.sendMu.
const signalingWriteTimeout = 10 * time.Second

// Max gap between client messages before we consider the WS dead. The client
// pings every minute (see SignalingConfiguration.pingFrequency), so anything
// past two missed pings is a silently-dropped connection we should reap.
// Mirrors Mojang's documented 120s inactivity timeout.
const signalingReadIdleTimeout = 2 * time.Minute

// Initial grace period: the spec also disconnects after 60s with no data
// received since the connection was established, independent of the 120s
// idle timer. Applied only to the first Receive.
const signalingInitialReadTimeout = time.Minute

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// {Code, Message} shape that SignalingErrorMapper.fromJsonRpc reads from error.data.
type rpcServiceErrorData struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// Relayed Signaling_ReceiveMessage_v1_0 payload. The vanilla
// ClientWebRtcMessage also has an optional "Id" field that we never set.
type receivedClientMessage struct {
	From    string `json:"From"`
	Message string `json:"Message"`
}

type turnAuthResult struct {
	ExpirationInSeconds int64            `json:"ExpirationInSeconds"`
	TurnAuthServers     []turnAuthServer `json:"TurnAuthServers"`
}

type turnAuthServer struct {
	Username string   `json:"Username"`
	Password string   `json:"Password"`
	Urls     []string `json:"Urls"`
}

// Hub keyed by pmid (dashed lowercase UUID).
type SignalingHub struct {
	mu       sync.RWMutex
	sessions map[string]*signalingSession
}

func NewSignalingHub() *SignalingHub {
	return &SignalingHub{sessions: make(map[string]*signalingSession)}
}

// Register a new session and return any sessions it replaces: the prior
// holder of the same pmid plus any other sessions belonging to the same
// player (a token refresh mints a fresh pmid, so the old WS would otherwise
// linger under a pmid that /presence no longer advertises). The caller must
// close the returned sessions outside the hub mutex.
func (h *SignalingHub) register(s *signalingSession) (replaced []*signalingSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur := h.sessions[s.pmid]; cur != nil && cur != s {
		replaced = append(replaced, cur)
	}
	for pmid, existing := range h.sessions {
		if pmid == s.pmid || existing == s {
			continue
		}
		if existing.playerUUID != "" && existing.playerUUID == s.playerUUID {
			replaced = append(replaced, existing)
		}
	}
	h.sessions[s.pmid] = s
	return replaced
}

func (h *SignalingHub) unregister(s *signalingSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.sessions[s.pmid]; ok && cur == s {
		delete(h.sessions, s.pmid)
	}
}

func (h *SignalingHub) lookup(pmid string) *signalingSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[pmid]
}

// Close every session belonging to the given player. Used when a player is
// deleted; calling s.close() reacquires the hub mutex via unregister, so we
// collect victims under the lock and close them after releasing it.
func (h *SignalingHub) closePlayer(playerUUID string) {
	if playerUUID == "" {
		return
	}
	h.mu.RLock()
	var victims []*signalingSession
	for _, s := range h.sessions {
		if s.playerUUID == playerUUID {
			victims = append(victims, s)
		}
	}
	h.mu.RUnlock()
	for _, s := range victims {
		s.close()
	}
}

type signalingSession struct {
	hub        *SignalingHub
	conn       *websocket.Conn
	pmid       string
	playerUUID string
	app        *App

	sendMu sync.Mutex
	once   sync.Once

	// Cached accepted-friend set. friendsTag is the FriendsETagStore etag
	// at the time we built it; a mismatch on next lookup invalidates.
	friendsMu  sync.Mutex
	friendsTag string
	friendsSet map[string]struct{}
}

// True if otherPlayerUUID is an accepted friend of this session's player.
// Caches the friend set per-session, revalidated by FriendsETagStore so
// we don't hit the DB on every relayed signaling message.
func (s *signalingSession) isFriendWith(otherPlayerUUID string) bool {
	if s.playerUUID == "" || otherPlayerUUID == "" || s.playerUUID == otherPlayerUUID {
		return false
	}
	tag := s.app.FriendsETagStore.etag(s.playerUUID)
	s.friendsMu.Lock()
	defer s.friendsMu.Unlock()
	if s.friendsSet == nil || s.friendsTag != tag {
		rows, err := s.app.friendshipsFor(s.playerUUID)
		if err != nil {
			return false
		}
		set := make(map[string]struct{}, len(rows))
		for _, r := range rows {
			if r.Status != FriendshipAccepted {
				continue
			}
			other := r.RecipientUUID
			if r.RecipientUUID == s.playerUUID {
				other = r.RequesterUUID
			}
			set[other] = struct{}{}
		}
		s.friendsSet = set
		s.friendsTag = tag
	}
	_, ok := s.friendsSet[otherPlayerUUID]
	return ok
}

func (s *signalingSession) close() {
	s.once.Do(func() {
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.hub.unregister(s)
	})
}

func (s *signalingSession) sendJSON(obj any) error {
	payload, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(signalingWriteTimeout)); err != nil {
		go s.close()
		return err
	}
	if _, err := s.conn.Write(payload); err != nil {
		// Partial write or timeout corrupts the WS frame stream; drop the
		// session so a stuck reader can't keep stalling future senders.
		go s.close()
		return err
	}
	return nil
}

func (s *signalingSession) sendNotification(method string, params any) error {
	env := rpcEnvelope{JSONRPC: "2.0", Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		env.Params = raw
	}
	return s.sendJSON(env)
}

func (s *signalingSession) sendResult(id json.RawMessage, result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return s.sendJSON(rpcEnvelope{JSONRPC: "2.0", ID: id, Result: raw})
}

func (s *signalingSession) sendError(id json.RawMessage, code int, message string, data any) error {
	return s.sendJSON(rpcEnvelope{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message, Data: data},
	})
}

// Validate the x-mojangauth header (raw access token, no "Bearer " prefix).
func (app *App) signalingAuthenticate(token string) (*Client, error) {
	if token == "" {
		return nil, errors.New("missing x-mojangauth")
	}
	return app.GetClient(token, mo.None[string](), StalePolicyAllow, true)
}

func signalingUnauthorized(c *echo.Context) error {
	return c.JSON(http.StatusUnauthorized, map[string]any{
		"path":         c.Request().URL.Path,
		"error":        "UNAUTHORIZED",
		"errorMessage": "Missing or invalid x-mojangauth",
	})
}

// GET {root}/api/v1.0/configuration/java
func (app *App) SignalingConfiguration(rootPath string) func(c *echo.Context) error {
	return func(c *echo.Context) error {
		if _, err := app.signalingAuthenticate(c.Request().Header.Get(signalingHeaderAuth)); err != nil {
			return signalingUnauthorized(c)
		}
		wsBase, err := signalingWSBaseURL(app.Config.BaseURL, rootPath)
		if err != nil {
			return err
		}
		// pingFrequency is hardcoded to 1 minute to match Mojang's behavior.
		return c.JSON(http.StatusOK, map[string]any{
			"result": map[string]any{"signalingUri": wsBase, "pingFrequency": "00:01:00"},
		})
	}
}

// Rewrite a BaseURL into ws[s]:// + rootPath. The client appends
// /ws/v1.0/messaging/connect/java to the result. setupSignaling rejects an
// empty BaseURL, so callers can rely on it being set here.
func signalingWSBaseURL(baseURL, rootPath string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(u.Scheme, "https") {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(u.Path, "/") + rootPath
	return u.String(), nil
}

// WS {root}/ws/v1.0/messaging/connect/java
func (app *App) SignalingWebSocket() func(c *echo.Context) error {
	return func(c *echo.Context) error {
		client, err := app.signalingAuthenticate(c.Request().Header.Get(signalingHeaderAuth))
		if err != nil {
			return signalingUnauthorized(c)
		}
		if client.Pmid == "" {
			return signalingUnauthorized(c)
		}
		pmid := client.Pmid
		playerUUID := client.Player.UUID

		srv := websocket.Server{
			Handshake: func(*websocket.Config, *http.Request) error { return nil },
			Handler: websocket.Handler(func(ws *websocket.Conn) {
				ws.PayloadType = websocket.TextFrame
				ws.MaxPayloadBytes = signalingMaxMessageBytes
				sess := &signalingSession{hub: app.SignalingHub, conn: ws, pmid: pmid, playerUUID: playerUUID, app: app}
				for _, old := range app.SignalingHub.register(sess) {
					old.close()
				}
				defer sess.close()
				sess.readLoop()
			}),
		}
		srv.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

func (s *signalingSession) readLoop() {
	first := true
	for {
		// Reset on every iteration so a healthy chatty connection isn't
		// killed mid-conversation, but a silently-dead one is reaped.
		// The first read uses a tighter 60s window to evict clients that
		// open the socket and then sit idle.
		timeout := signalingReadIdleTimeout
		if first {
			timeout = signalingInitialReadTimeout
		}
		if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
		var raw []byte
		// Receive a whole message; MaxPayloadBytes on the Conn caps the size
		// so we never see a frame that would have to be split across reads.
		if err := websocket.Message.Receive(s.conn, &raw); err != nil {
			return
		}
		first = false
		if len(raw) == 0 {
			continue
		}
		s.dispatch(raw)
	}
}

func (s *signalingSession) dispatch(payload []byte) {
	var env rpcEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return
	}
	// Responses to server-initiated requests are dropped; we don't track them.
	if env.Method != "" && env.Result == nil && env.Error == nil {
		hasID := len(env.ID) > 0 && string(env.ID) != "null"
		s.handleMethod(env, hasID)
	}
}

func (s *signalingSession) handleMethod(env rpcEnvelope, hasID bool) {
	var id json.RawMessage
	if hasID {
		id = env.ID
	}
	switch env.Method {
	case signalingMethodPing:
		_ = s.sendNotification(signalingMethodPong, nil)
	case signalingMethodTurnAuth:
		s.handleTurnAuth(id)
	case signalingMethodSendClientMsg:
		s.handleSendClientMessage(id, env.Params)
	default:
		if hasID {
			_ = s.sendError(id, -32601, "Method not found", env.Method)
		}
	}
}

func (s *signalingSession) handleTurnAuth(id json.RawMessage) {
	if id == nil {
		return
	}
	var player Player
	if err := s.app.DB.Preload("User").First(&player, "uuid = ?", s.playerUUID).Error; err != nil {
		_ = s.sendError(id, signalingErrServiceCode, "Player not found", nil)
		return
	}
	if player.User.IsLocked {
		_ = s.sendError(id, signalingErrServiceCode, "Account is locked", nil)
		return
	}
	_ = s.sendResult(id, turnAuthResult{
		ExpirationInSeconds: int64(signalingTurnTTL.Seconds()),
		TurnAuthServers:     s.app.turnAuthServers(s.pmid),
	})
}

// Params shape: [null, toPmid, encodedMessageJson].
func (s *signalingSession) handleSendClientMessage(id json.RawMessage, params json.RawMessage) {
	invalidParams := func() {
		if id != nil {
			_ = s.sendError(id, -32602, "Invalid params", nil)
		}
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) < 3 {
		invalidParams()
		return
	}
	var toPmid, encoded string
	if json.Unmarshal(arr[1], &toPmid) != nil || toPmid == "" ||
		json.Unmarshal(arr[2], &encoded) != nil {
		invalidParams()
		return
	}

	target := s.hub.lookup(strings.ToLower(toPmid))
	// Treat non-friends the same as offline: an attacker who learned a pmid
	// shouldn't be able to probe or inject signaling messages, and a
	// formerly-friended pmid stops working as soon as the friendship ends.
	if target == nil || !s.isFriendWith(target.playerUUID) {
		if id != nil {
			_ = s.sendError(id, signalingErrServiceCode,
				"Player unreachable",
				rpcServiceErrorData{Code: signalingErrDataUnknownPlayer, Message: "Player is not connected"})
		}
		return
	}

	payload := []any{receivedClientMessage{From: s.pmid, Message: encoded}}
	if err := target.sendNotification(signalingMethodReceiveMessage, payload); err != nil {
		if id != nil {
			_ = s.sendError(id, signalingErrServiceCode,
				"Message delivery failed",
				rpcServiceErrorData{Code: "DeliveryFailed", Message: err.Error()})
		}
		return
	}
	if id != nil {
		// Spec result is null; vanilla client only inspects error.
		_ = s.sendResult(id, nil)
	}
}

// True if the configured TURN relay address is itself non-routable
// (loopback / RFC1918 / ULA / link-local / CGNAT), indicating a LAN-only
// deployment where filtering peer addresses to public space would block
// the obvious legitimate use.
func turnRelayIsPrivate(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// Build the PermissionHandler for the embedded TURN server. When relayIP is
// public, peers are clamped to ordinary unicast public addresses so a drasl
// account can't coerce the relay into probing the operator's internal
// network. When relayIP is itself private/loopback the deployment is LAN-
// scoped and we admit every peer (matching pion's DefaultPermissionHandler).
func turnPermissionHandler(relayIP net.IP) turn.PermissionHandler {
	if turnRelayIsPrivate(relayIP) {
		return turn.DefaultPermissionHandler
	}
	return func(_ net.Addr, peerIP net.IP) bool {
		if peerIP == nil || peerIP.IsUnspecified() {
			return false
		}
		if peerIP.IsLoopback() || peerIP.IsPrivate() {
			return false
		}
		if peerIP.IsLinkLocalUnicast() || peerIP.IsLinkLocalMulticast() {
			return false
		}
		if peerIP.IsInterfaceLocalMulticast() || peerIP.IsMulticast() {
			return false
		}
		// 100.64.0.0/10 (RFC 6598 CGNAT) is not covered by IsPrivate.
		if v4 := peerIP.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		return true
	}
}

// Wrap pion's REST-API AuthHandler with a presence check: the username we
// issue is "<unix-expiry>:<pmid>", so a TURN allocate or refresh is only
// accepted while that pmid still has a live signaling WS. A player who goes
// offline (or whose token rotates, dropping the old pmid) loses TURN access
// at the next allocate/refresh even if their credentials haven't yet expired.
func turnHubAuthHandler(secret string, hub *SignalingHub, logger logging.LeveledLogger) turn.AuthHandler {
	inner := turn.LongTermTURNRESTAuthHandler(secret, logger)
	return func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
		parts := strings.SplitN(username, ":", 2)
		if len(parts) < 2 || parts[1] == "" {
			return nil, false
		}
		if hub.lookup(strings.ToLower(parts[1])) == nil {
			return nil, false
		}
		return inner(username, realm, srcAddr)
	}
}

// Return the configured TURN auth secret, or load/create a persisted one in
// the state directory. Persisting matters because the secret signs the
// long-term TURN credentials advertised to clients; losing it on every
// restart invalidates every active TURN allocation across all users.
func resolveTURNAuthSecret(configured, stateDir string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	if stateDir == "" {
		return "", errors.New("StateDirectory must be set to persist a generated TURN auth secret")
	}
	path := filepath.Join(stateDir, "turn-auth-secret")
	if existing, err := os.ReadFile(path); err == nil {
		secret := strings.TrimSpace(string(existing))
		if secret != "" {
			return secret, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return secret, nil
}

// Embedded TURN server. Started by setupSignaling when P2P.Enable=true,
// no ExternalTURNServers are configured, and P2P.TURNPublicIP is set.

type embeddedTURN struct {
	publicHost string // host:port advertised in client URLs
	authSecret string
}

func setupSignaling(app *App) error {
	if !app.Config.P2P.Enable {
		return nil
	}
	if app.Config.BaseURL == "" {
		// /api/v1.0/configuration/java would otherwise hand clients
		// ws://localhost/..., which is unreachable from any other host.
		return errors.New("P2P.Enable = true requires Config.BaseURL to be set")
	}
	if len(app.Config.ExternalTURNServers) > 0 {
		return nil // client will be pointed at the externally-configured servers
	}
	publicIP := app.Config.P2P.TURNPublicIP
	if publicIP == "" {
		return fmt.Errorf("P2P.Enable = true requires either P2P.TURNPublicIP or [[ExternalTURNServers]]")
	}
	relayIP := net.ParseIP(publicIP)
	if relayIP == nil {
		return fmt.Errorf("invalid P2P.TURNPublicIP: %q", publicIP)
	}
	network, relayBind := "udp4", "0.0.0.0"
	if relayIP.To4() == nil {
		network, relayBind = "udp6", "::"
	}

	listen := app.Config.P2P.TURNListenAddress
	udp, err := net.ListenPacket(network, listen)
	if err != nil {
		return fmt.Errorf("TURN listen on %s: %w", listen, err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port

	secret, err := resolveTURNAuthSecret(app.Config.P2P.TURNAuthSecret, app.Config.StateDirectory)
	if err != nil {
		_ = udp.Close()
		return err
	}

	realm := app.Config.Domain
	if realm == "" {
		realm = "drasl"
	}

	logger := logging.NewDefaultLoggerFactory()
	if _, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   turnHubAuthHandler(secret, app.SignalingHub, logger.NewLogger("turn-auth")),
		LoggerFactory: logger,
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udp,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: relayIP,
				Address:      relayBind,
			},
			PermissionHandler: turnPermissionHandler(relayIP),
		}},
	}); err != nil {
		_ = udp.Close()
		return err
	}

	app.TURN = &embeddedTURN{
		publicHost: net.JoinHostPort(publicIP, strconv.Itoa(port)),
		authSecret: secret,
	}
	log.Printf("Embedded TURN server listening on %s (relay %s)", listen, app.TURN.publicHost)
	return nil
}

func (app *App) turnAuthServers(pmid string) []turnAuthServer {
	if len(app.Config.ExternalTURNServers) > 0 {
		out := make([]turnAuthServer, 0, len(app.Config.ExternalTURNServers))
		for _, s := range app.Config.ExternalTURNServers {
			user, pass := s.Username, s.Password
			if s.Secret != "" {
				u, p, err := turn.GenerateLongTermTURNRESTCredentials(s.Secret, pmid, signalingTurnTTL)
				if err != nil {
					log.Printf("TURN credential generation failed for %v: %s", s.Urls, err)
					continue
				}
				user, pass = u, p
			}
			out = append(out, turnAuthServer{Username: user, Password: pass, Urls: s.Urls})
		}
		return out
	}
	if app.TURN == nil {
		return nil
	}
	user, pass, err := turn.GenerateLongTermTURNRESTCredentials(app.TURN.authSecret, pmid, signalingTurnTTL)
	if err != nil {
		log.Printf("TURN credential generation failed: %s", err)
		return nil
	}
	return []turnAuthServer{{
		Username: user,
		Password: pass,
		Urls:     []string{"turn:" + app.TURN.publicHost},
	}}
}
