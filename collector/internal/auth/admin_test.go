package auth

import "testing"

func TestAdminStore_AddAndVerify(t *testing.T) {
	as := NewAdminStore()
	as.Add("ops-laptop", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	name, ok := as.Verify("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if !ok {
		t.Fatal("expected Verify to succeed for registered admin key")
	}
	if name != "ops-laptop" {
		t.Fatalf("expected admin name 'ops-laptop', got %q", name)
	}
}

func TestAdminStore_VerifyRejectsUnknown(t *testing.T) {
	as := NewAdminStore()
	as.Add("ops-laptop", "aaaa")
	if _, ok := as.Verify("bbbb"); ok {
		t.Fatal("expected Verify to reject unknown key")
	}
}

func TestAdminStore_VerifyRejectsEmpty(t *testing.T) {
	as := NewAdminStore()
	if _, ok := as.Verify(""); ok {
		t.Fatal("expected Verify to reject empty key")
	}
}
