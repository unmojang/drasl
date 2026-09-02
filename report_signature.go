package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	reportMessageVerified           = "VERIFIED"
	reportMessageMissingSignature   = "MISSING_SIGNATURE"
	reportMessageUnknownCertificate = "UNKNOWN_CERTIFICATE"
	reportMessageInvalidSignature   = "INVALID_SIGNATURE"
	reportMessageBrokenChain        = "BROKEN_CHAIN"
)

type reportEvidenceMessage struct {
	ProfileID       string   `json:"profileId"`
	SessionID       string   `json:"sessionId,omitempty"`
	Index           int32    `json:"index,omitempty"`
	Timestamp       string   `json:"timestamp"`
	Message         string   `json:"message"`
	Signature       string   `json:"signature,omitempty"`
	LastSeen        []string `json:"lastSeen,omitempty"`
	MessageReported bool     `json:"messageReported"`
	Status          string   `json:"status"`
	Problem         string   `json:"problem,omitempty"`
	Certificate     string   `json:"certificate,omitempty"`
	OutOfWindow     int      `json:"outOfWindowReferences,omitempty"`
}

type modernReportMessage struct {
	Index           int32     `json:"index"`
	ProfileID       string    `json:"profileId"`
	SessionID       string    `json:"sessionId"`
	Timestamp       time.Time `json:"timestamp"`
	Salt            int64     `json:"salt"`
	LastSeen        []string  `json:"lastSeen"`
	Message         string    `json:"message"`
	Signature       string    `json:"signature"`
	MessageReported bool      `json:"messageReported"`
}

type legacyReportMessage struct {
	Header struct {
		PreviousSignature *string `json:"signatureOfPreviousHeader"`
		ProfileID         string  `json:"profileId"`
		HashOfBody        string  `json:"hashOfBody"`
		Signature         string  `json:"signature"`
	} `json:"header"`
	Body struct {
		Timestamp          time.Time `json:"timestamp"`
		Salt               int64     `json:"salt"`
		LastSeenSignatures []struct {
			ProfileID string `json:"profileId"`
			Signature string `json:"signature"`
		} `json:"lastSeenSignatures"`
		Message struct {
			Plain     string          `json:"plain"`
			Decorated json.RawMessage `json:"decorated"`
		} `json:"message"`
	} `json:"body"`
	MessageReported bool `json:"messageReported"`
}

func uuidBytes(value string) ([]byte, error) {
	parsed, err := uuid.Parse(value)
	if err != nil {
		return nil, err
	}
	return parsed[:], nil
}

func decodeReportSignature(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("missing signature")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 256 {
		return nil, errors.New("signature is not a base64 RSA-2048 signature")
	}
	return decoded, nil
}

func certificatePublicKey(cert *PlayerCertificate) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(cert.PublicKeyDER)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok || rsaKey.Size() != 256 {
		return nil, errors.New("certificate does not contain an RSA-2048 key")
	}
	return rsaKey, nil
}

func verifyCertificateV2(root *rsa.PublicKey, cert *PlayerCertificate) bool {
	if len(cert.PublicKeySignatureV2) == 0 {
		return false
	}
	playerID, err := uuidBytes(cert.PlayerUUID)
	if err != nil {
		return false
	}
	payload := make([]byte, 0, 24+len(cert.PublicKeyDER))
	payload = append(payload, playerID...)
	expires := make([]byte, 8)
	binary.BigEndian.PutUint64(expires, uint64(cert.ExpiresAt.UnixMilli()))
	payload = append(payload, expires...)
	payload = append(payload, cert.PublicKeyDER...)
	digest := sha1.Sum(payload)
	return rsa.VerifyPKCS1v15(root, crypto.SHA1, digest[:], cert.PublicKeySignatureV2) == nil
}

func reportCertificateCandidates(app *App, playerUUID string, timestamp time.Time) ([]PlayerCertificate, error) {
	var certificates []PlayerCertificate
	if err := app.DB.Where("player_uuid = ? AND issued_at <= ? AND expires_at >= ?", playerUUID, timestamp.Add(5*time.Minute), timestamp.Add(-5*time.Minute)).Find(&certificates).Error; err != nil {
		return nil, err
	}
	valid := certificates[:0]
	for i := range certificates {
		cert := &certificates[i]
		// Both vanilla report generations start at 1.19.1 and use the V2
		// certificate binding. V1 is issued only for 1.19.0 secure-profile
		// compatibility; that client has no vanilla report format.
		if !verifyCertificateV2(&app.PrivateKey.PublicKey, cert) {
			continue
		}
		if _, err := certificatePublicKey(cert); err == nil {
			valid = append(valid, *cert)
		}
	}
	return valid, nil
}

func buildModernSignedPayload(message *modernReportMessage) ([]byte, error) {
	profileID, err := uuidBytes(message.ProfileID)
	if err != nil {
		return nil, err
	}
	sessionID, err := uuidBytes(message.SessionID)
	if err != nil {
		return nil, err
	}
	if len(message.LastSeen) > 20 {
		return nil, errors.New("more than 20 last-seen signatures")
	}

	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.BigEndian, int32(1))
	payload.Write(profileID)
	payload.Write(sessionID)
	_ = binary.Write(&payload, binary.BigEndian, message.Index)
	_ = binary.Write(&payload, binary.BigEndian, message.Salt)
	_ = binary.Write(&payload, binary.BigEndian, message.Timestamp.Unix())
	messageBytes := []byte(message.Message)
	_ = binary.Write(&payload, binary.BigEndian, int32(len(messageBytes)))
	payload.Write(messageBytes)
	_ = binary.Write(&payload, binary.BigEndian, int32(len(message.LastSeen)))
	for _, encoded := range message.LastSeen {
		signature, err := decodeReportSignature(encoded)
		if err != nil {
			return nil, err
		}
		payload.Write(signature)
	}
	return payload.Bytes(), nil
}

func verifyWithCertificates(candidates []PlayerCertificate, payload, signature []byte) (string, bool) {
	digest := sha256.Sum256(payload)
	for i := range candidates {
		key, err := certificatePublicKey(&candidates[i])
		if err == nil && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil {
			return candidates[i].Fingerprint, true
		}
	}
	return "", false
}

func verifyModernMessage(app *App, message *modernReportMessage) reportEvidenceMessage {
	result := reportEvidenceMessage{
		ProfileID: message.ProfileID, SessionID: message.SessionID, Index: message.Index,
		Timestamp: message.Timestamp.UTC().Format(time.RFC3339Nano), Message: message.Message,
		Signature: message.Signature, LastSeen: message.LastSeen, MessageReported: message.MessageReported,
	}
	parsedID, err := ParseUUID(message.ProfileID)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, "invalid author UUID"
		return result
	}
	result.ProfileID = parsedID
	if _, err := ParseUUID(message.SessionID); err != nil || message.Timestamp.IsZero() {
		result.Status, result.Problem = reportMessageInvalidSignature, "invalid session or timestamp"
		return result
	}
	signature, err := decodeReportSignature(message.Signature)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, err.Error()
		if message.Signature == "" {
			result.Status = reportMessageMissingSignature
		}
		return result
	}
	payload, err := buildModernSignedPayload(message)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, err.Error()
		return result
	}
	candidates, err := reportCertificateCandidates(app, parsedID, message.Timestamp)
	if err != nil {
		result.Status, result.Problem = reportMessageUnknownCertificate, "certificate lookup failed"
		return result
	}
	if len(candidates) == 0 {
		result.Status, result.Problem = reportMessageUnknownCertificate, "no trusted certificate covers this message"
		return result
	}
	if fingerprint, ok := verifyWithCertificates(candidates, payload, signature); ok {
		result.Status, result.Certificate = reportMessageVerified, fingerprint
	} else {
		result.Status, result.Problem = reportMessageInvalidSignature, "signature verification failed"
	}
	return result
}

func canonicalReportJSON(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func buildLegacyBodyHash(message *legacyReportMessage) ([]byte, error) {
	if len(message.Body.LastSeenSignatures) > 5 {
		return nil, errors.New("more than five legacy last-seen signatures")
	}
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, message.Body.Salt)
	_ = binary.Write(&body, binary.BigEndian, message.Body.Timestamp.Unix())
	body.WriteString(message.Body.Message.Plain)
	body.WriteByte(0x46)
	if decorated, err := canonicalReportJSON(message.Body.Message.Decorated); err != nil {
		return nil, err
	} else if len(decorated) > 0 {
		body.Write(decorated)
	}
	for _, seen := range message.Body.LastSeenSignatures {
		profileID, err := uuidBytes(seen.ProfileID)
		if err != nil {
			return nil, err
		}
		signature, err := decodeReportSignature(seen.Signature)
		if err != nil {
			return nil, err
		}
		body.WriteByte(0x46)
		body.Write(profileID)
		body.Write(signature)
	}
	hash := sha256.Sum256(body.Bytes())
	return hash[:], nil
}

func buildLegacySignedPayload(message *legacyReportMessage, bodyHash []byte) ([]byte, error) {
	var payload bytes.Buffer
	if message.Header.PreviousSignature != nil {
		previous, err := decodeReportSignature(*message.Header.PreviousSignature)
		if err != nil {
			return nil, err
		}
		payload.Write(previous)
	}
	profileID, err := uuidBytes(message.Header.ProfileID)
	if err != nil {
		return nil, err
	}
	payload.Write(profileID)
	payload.Write(bodyHash)
	return payload.Bytes(), nil
}

func verifyLegacyMessage(app *App, message *legacyReportMessage) reportEvidenceMessage {
	lastSeen := make([]string, 0, len(message.Body.LastSeenSignatures))
	for _, seen := range message.Body.LastSeenSignatures {
		lastSeen = append(lastSeen, seen.Signature)
	}
	result := reportEvidenceMessage{
		ProfileID: message.Header.ProfileID, Timestamp: message.Body.Timestamp.UTC().Format(time.RFC3339Nano),
		Message: message.Body.Message.Plain, Signature: message.Header.Signature,
		LastSeen: lastSeen, MessageReported: message.MessageReported,
	}
	parsedID, err := ParseUUID(message.Header.ProfileID)
	if err != nil || message.Body.Timestamp.IsZero() {
		result.Status, result.Problem = reportMessageInvalidSignature, "invalid author UUID or timestamp"
		return result
	}
	result.ProfileID = parsedID
	signature, err := decodeReportSignature(message.Header.Signature)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, err.Error()
		if message.Header.Signature == "" {
			result.Status = reportMessageMissingSignature
		}
		return result
	}
	bodyHash, err := buildLegacyBodyHash(message)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, err.Error()
		return result
	}
	declaredHash, err := base64.StdEncoding.DecodeString(message.Header.HashOfBody)
	if err != nil || !bytes.Equal(declaredHash, bodyHash) {
		result.Status, result.Problem = reportMessageInvalidSignature, "body hash does not match the message"
		return result
	}
	payload, err := buildLegacySignedPayload(message, bodyHash)
	if err != nil {
		result.Status, result.Problem = reportMessageInvalidSignature, err.Error()
		return result
	}
	candidates, err := reportCertificateCandidates(app, parsedID, message.Body.Timestamp)
	if err != nil || len(candidates) == 0 {
		result.Status, result.Problem = reportMessageUnknownCertificate, "no certificate covers this message"
		return result
	}
	if fingerprint, ok := verifyWithCertificates(candidates, payload, signature); ok {
		result.Status, result.Certificate = reportMessageVerified, fingerprint
	} else {
		result.Status, result.Problem = reportMessageInvalidSignature, "signature verification failed"
	}
	return result
}

func markModernChainProblems(messages []reportEvidenceMessage) {
	bySignature := make(map[string]int, len(messages))
	chainIndex := make(map[string]int)
	for i := range messages {
		if messages[i].Signature != "" {
			bySignature[messages[i].Signature] = i
		}
		key := messages[i].ProfileID + ":" + messages[i].SessionID + fmt.Sprintf(":%d", messages[i].Index)
		if previous, ok := chainIndex[key]; ok && messages[previous].Signature != messages[i].Signature {
			messages[previous].Status, messages[previous].Problem = reportMessageBrokenChain, "conflicting messages use the same chain index"
			messages[i].Status, messages[i].Problem = reportMessageBrokenChain, "conflicting messages use the same chain index"
		} else {
			chainIndex[key] = i
		}
	}
	for i := range messages {
		for _, reference := range messages[i].LastSeen {
			referencedIndex, ok := bySignature[reference]
			if !ok {
				messages[i].OutOfWindow++
				continue
			}
			referenced := messages[referencedIndex]
			if referencedIndex == i || referenced.Status != reportMessageVerified ||
				(referenced.ProfileID == messages[i].ProfileID && referenced.SessionID == messages[i].SessionID && referenced.Index >= messages[i].Index) {
				messages[i].Status, messages[i].Problem = reportMessageBrokenChain, "last-seen reference contradicts the included evidence"
			}
		}
	}
}

func reportAttestation(messages []reportEvidenceMessage) ReportAttestation {
	verified := 0
	for i := range messages {
		if messages[i].Status == reportMessageVerified {
			verified++
		}
	}
	if verified == len(messages) && verified > 0 {
		return ReportAttestationAttested
	}
	if verified > 0 {
		return ReportAttestationPartial
	}
	return ReportAttestationUnattested
}
