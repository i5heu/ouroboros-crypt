package async

import "testing"

func TestSignAndVerify(t *testing.T) {
	ac, err := NewAsyncCrypt()
	if err != nil {
		t.Fatalf("NewAsyncCrypt returned error: %v", err)
	}
	data := []byte("test data")
	sig, err := ac.Sign(data)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if !ac.Verify(data, sig) {
		t.Errorf("Verify failed for valid signature")
	}
}

func TestVerifyAlteredData(t *testing.T) {
	ac, err := NewAsyncCrypt()
	if err != nil {
		t.Fatalf("NewAsyncCrypt returned error: %v", err)
	}
	data := []byte("test message")
	sig, err := ac.Sign(data)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	altered := []byte("altered message")
	if ac.Verify(altered, sig) {
		t.Error("Verify passed for altered data")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	ac, err := NewAsyncCrypt()
	if err != nil {
		t.Fatalf("NewAsyncCrypt returned error: %v", err)
	}
	data := []byte("another test")
	invalidSig := []byte("not a valid signature")
	if ac.Verify(data, invalidSig) {
		t.Error("Verify passed for invalid signature")
	}
}
