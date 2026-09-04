package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// This vector was produced by Minecraft 26.2's own
// PlayerChatMessage.updateSignature implementation.
func TestModernReportSignatureVector(t *testing.T) {
	publicDER := Unwrap(base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3U4PvMkPAnm8WLQwKiXX+UFmlZnnsMiyaIxag8Om2Fc0QqtiETEz/zm4Codl4CUpapsOQOXQ88Fr3ypEFsfgehkH/3X5BqVWj0rGDBp6howBGlsJ/gAAqqIS4vn4LqfzLS7TbmtD/DnEIOnKdvM0P0FUTq/YwE0L629o6SuN+W7LJHWPX9+dI6ZFZ+BQ1ciByR7M/YLvRAdtzQOkE534+vvWggJyxxuoxXkneXvVO+ACehmkkhYdgszg69MpYIe9Zdt6hypxmgYcGHVydVp99PSCrVavON9bKPGI/xCAezS1naQZ3y5FJ3ECNrKT1XSRY7W1rvFLz/ktN4FMZ7H0eQIDAQAB"))
	key := Unwrap(x509.ParsePKIXPublicKey(publicDER)).(*rsa.PublicKey)
	message := modernReportMessage{
		Index: 0, ProfileID: "11111111-2222-3333-4444-555555555555",
		SessionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Timestamp: Unwrap(time.Parse(time.RFC3339Nano, "2026-05-28T20:26:40.567Z")),
		Salt:      0, Message: "hello world", LastSeen: []string{},
	}
	payload := Unwrap(buildModernSignedPayload(&message))
	digest := sha256.Sum256(payload)
	signature := Unwrap(base64.StdEncoding.DecodeString("nHN9fpinwNRYhQdAAQiFi40s2WtJ/fhmh/ry6RNqNaAQ/LAPCBYxU+Ds5tClEQE/YiNoSoUQKVedBtBkHp9mwqiCjMKzbzDrt8MWQMjbAQ3sI94p3jkDHQbkHmNMNEzhW2K3LGFJsWSE6K0LciTjj7Yl8voIhyzO+1p9ae0drq55o6eRolkQxmw9OMvl9eA92l1ed469E0z7PlIDvidKn0UyUp3c1cpdOcZoqNLTf3M1QzaS9oCIryL0b2HJXlw4u3Jfq+QauKnUfz+v1z7sEQ0H47zTPUl4d+XHI3nvmpXnsETtxnxYQ12RkFmrBeSGy3cVkwZr0Q2bwcqn9/tNog=="))
	assert.NoError(t, rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature))

	message.Message = "altered"
	payload = Unwrap(buildModernSignedPayload(&message))
	digest = sha256.Sum256(payload)
	assert.Error(t, rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature))
}

func TestReportReasonCompatibility(t *testing.T) {
	_, reason, err := normalizeReportReason("modern-multitype-v1", ReportTypeChat, Ptr("GENERIC"))
	assert.NoError(t, err)
	assert.Equal(t, "I_WANT_TO_REPORT_THEM", reason.String)

	_, _, err = normalizeReportReason("modern-chat-v1", ReportTypeChat, Ptr("GENERIC"))
	assert.Error(t, err)
	_, _, err = normalizeReportReason("modern-multitype-v1", ReportTypeChat, Ptr("SEXUALLY_INAPPROPRIATE"))
	assert.Error(t, err)
	_, _, err = normalizeReportReason("modern-multitype-v1", ReportTypeSkin, Ptr("IMMINENT_HARM"))
	assert.Error(t, err)
	_, _, err = normalizeReportReason("legacy-chat-v0", ReportTypeChat, Ptr("FALSE_REPORTING"))
	assert.Error(t, err)
}
