package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
	maxSafeOrderID      float64        = 9007199254740991 // 2^53 - 1, the maximum safe integer in JavaScript
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey string, expectedKey string, payload any) WebhookVerification {
	// Caller is responsible for ensuring that providedKey and expectedKey are non-empty.
	if len(providedKey) != len(expectedKey) {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	if payload == nil {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || orderID <= 0 || orderID > maxSafeOrderID {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	if math.Trunc(orderID) != orderID {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderStatus, ok := payloadRecord["status"].(string)
	if !ok || orderStatus != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
