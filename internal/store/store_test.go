package store

import (
	"path/filepath"
	"testing"
)

func TestCreateValidateRevoke(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	res, err := s.CreateKey("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Plaintext == "" || res.Key.ID == "" {
		t.Fatal("missing plaintext or id")
	}
	if res.Key.KeyPrefix == "" {
		t.Fatal("expected key prefix")
	}

	got, err := s.ValidatePlaintext(res.Plaintext)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.ID != res.Key.ID {
		t.Fatalf("id mismatch")
	}

	if _, err := s.ValidatePlaintext("sk-gap-invalid"); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}

	if err := s.RevokeKey(res.Key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidatePlaintext(res.Plaintext); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized after revoke, got %v", err)
	}

	keys, err := s.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Enabled {
		t.Fatalf("list after revoke: %+v", keys)
	}
}

func TestRevokeNotFound(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RevokeKey("does-not-exist"); err != ErrNotFound {
		t.Fatalf("got %v", err)
	}
}
