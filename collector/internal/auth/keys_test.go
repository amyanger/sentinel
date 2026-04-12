package auth

import "testing"

func TestKeyStore_AddAndVerify(t *testing.T) {
	ks := NewKeyStore()
	ks.Add("client-a", "secret-a")
	ks.Add("client-b", "secret-b")

	if name, ok := ks.Verify("secret-a"); !ok || name != "client-a" {
		t.Errorf("Verify(secret-a): got (%q, %v), want (client-a, true)", name, ok)
	}
	if _, ok := ks.Verify("wrong"); ok {
		t.Errorf("Verify(wrong): expected false")
	}
	if _, ok := ks.Verify(""); ok {
		t.Errorf("Verify(empty): expected false")
	}
}

func TestParseBearer(t *testing.T) {
	cases := map[string]struct {
		header   string
		want     string
		wantOK   bool
	}{
		"ok":          {"Bearer abc123", "abc123", true},
		"no prefix":   {"abc123", "", false},
		"wrong case":  {"bearer abc123", "abc123", true}, // case-insensitive scheme
		"empty":       {"", "", false},
		"only bearer": {"Bearer ", "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := ParseBearer(tc.header)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
