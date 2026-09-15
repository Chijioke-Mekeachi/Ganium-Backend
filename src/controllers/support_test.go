package controllers

import (
	"testing"

	"ganium/src/models"
)

func TestNormalizeSupportStatus(t *testing.T) {
	for _, status := range []string{"open", "PENDING", "resolved", "closed"} {
		normalized, err := normalizeSupportStatus(status)
		if err != nil {
			t.Fatalf("expected valid status %q but got error: %v", status, err)
		}
		if !models.IsValidSupportStatus(normalized) {
			t.Fatalf("status %q normalized to %q but should be valid", status, normalized)
		}
	}

	if _, err := normalizeSupportStatus("archived"); err == nil {
		t.Fatal("expected invalid status to fail validation")
	}
}

func TestNormalizeSupportMessage(t *testing.T) {
	if _, err := normalizeSupportMessage("   "); err == nil {
		t.Fatal("expected empty message to fail")
	}

	if _, err := normalizeSupportMessage("hello"); err != nil {
		t.Fatalf("expected non-empty message to pass, got %v", err)
	}
}

func TestSenderTypeForRole(t *testing.T) {
	if got := senderTypeForRole("admin"); got != models.SupportSenderSupport {
		t.Fatalf("expected admin sender type to be %q, got %q", models.SupportSenderSupport, got)
	}
	if got := senderTypeForRole("user"); got != models.SupportSenderUser {
		t.Fatalf("expected user sender type to be %q, got %q", models.SupportSenderUser, got)
	}
}

func TestSupportQueryParamInt(t *testing.T) {
	if got := SupportQueryParamInt("0", 3); got != 3 {
		t.Fatalf("expected default value 3 for zero or invalid page, got %d", got)
	}
	if got := SupportQueryParamInt("7", 3); got != 7 {
		t.Fatalf("expected page value 7, got %d", got)
	}
}
