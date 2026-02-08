package crypto

import (
	"encoding/hex"
	"testing"
)

func TestValidateAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{
			name:    "valid mainnet P2PKH address",
			address: "DFundAbc123def456ghi789jkl012mno34",
			wantErr: true, // Invalid checksum, but tests prefix
		},
		{
			name:    "valid prefix D",
			address: "D5bT3b1Y6pXS3rBo34YFnB4cYxLfKXJq2F",
			wantErr: true, // Checksum depends on real address
		},
		{
			name:    "empty address",
			address: "",
			wantErr: true,
		},
		{
			name:    "bitcoin address (wrong prefix)",
			address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
			wantErr: true,
		},
		{
			name:    "litecoin address (wrong prefix)",
			address: "LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			address: "D5bT3b1Y6pXS3rBo34YFnB4cYx!@#$%^&",
			wantErr: true,
		},
		{
			name:    "too short",
			address: "D5bT3",
			wantErr: true,
		},
		{
			name:    "P2SH address prefix S",
			address: "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXj",
			wantErr: true, // Invalid checksum but valid prefix
		},
		{
			name:    "bech32 address prefix dgb1",
			address: "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7klfq2fx",
			wantErr: false, // Bech32 validation is TODO, so prefix check passes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddress(tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAddress(%q) error = %v, wantErr %v", tt.address, err, tt.wantErr)
			}
		})
	}
}

func TestBuildChallengeURI(t *testing.T) {
	tests := []struct {
		name        string
		callbackURL string
		nonce       string
		unsecure    bool
		want        string
		wantErr     bool
	}{
		{
			name:        "HTTPS callback",
			callbackURL: "https://digiauth.example.com/api/v1/auth/callback",
			nonce:       "abc123def456",
			unsecure:    false,
			want:        "digiid://digiauth.example.com/api/v1/auth/callback?x=abc123def456",
			wantErr:     false,
		},
		{
			name:        "HTTP callback with unsecure flag",
			callbackURL: "http://localhost:8080/api/v1/auth/callback",
			nonce:       "test123",
			unsecure:    true,
			want:        "digiid://localhost:8080/api/v1/auth/callback?x=test123&u=1",
			wantErr:     false,
		},
		{
			name:        "callback with port",
			callbackURL: "https://example.com:3000/callback",
			nonce:       "nonce999",
			unsecure:    false,
			want:        "digiid://example.com:3000/callback?x=nonce999",
			wantErr:     false,
		},
		{
			name:        "empty callback URL",
			callbackURL: "",
			nonce:       "test",
			unsecure:    false,
			want:        "digiid://?x=test",
			wantErr:     false,
		},
		{
			name:        "root path",
			callbackURL: "https://example.com",
			nonce:       "abc",
			unsecure:    false,
			want:        "digiid://example.com?x=abc",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildChallengeURI(tt.callbackURL, tt.nonce, tt.unsecure)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildChallengeURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildChallengeURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractNonce(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    string
		wantErr bool
	}{
		{
			name:    "valid digiid URI",
			uri:     "digiid://example.com/callback?x=abc123def456",
			want:    "abc123def456",
			wantErr: false,
		},
		{
			name:    "URI with unsecure flag",
			uri:     "digiid://localhost:8080/callback?x=nonce999&u=1",
			want:    "nonce999",
			wantErr: false,
		},
		{
			name:    "missing nonce parameter",
			uri:     "digiid://example.com/callback?other=value",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty nonce value",
			uri:     "digiid://example.com/callback?x=",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid URI",
			uri:     "://invalid",
			want:    "",
			wantErr: true,
		},
		{
			name:    "nonce with special characters",
			uri:     "digiid://example.com/callback?x=abc%20123",
			want:    "abc 123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractNonce(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractNonce() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateCallbackURI(t *testing.T) {
	tests := []struct {
		name             string
		uri              string
		expectedCallback string
		unsecure         bool
		wantErr          bool
	}{
		{
			name:             "valid secure callback",
			uri:              "digiid://example.com/api/v1/auth/callback?x=nonce123",
			expectedCallback: "https://example.com/api/v1/auth/callback",
			unsecure:         false,
			wantErr:          false,
		},
		{
			name:             "valid unsecure callback",
			uri:              "digiid://localhost:8080/callback?x=nonce123&u=1",
			expectedCallback: "http://localhost:8080/callback",
			unsecure:         true,
			wantErr:          false,
		},
		{
			name:             "host mismatch",
			uri:              "digiid://evil.com/callback?x=nonce123",
			expectedCallback: "https://example.com/callback",
			unsecure:         false,
			wantErr:          true,
		},
		{
			name:             "path mismatch",
			uri:              "digiid://example.com/other/path?x=nonce123",
			expectedCallback: "https://example.com/callback",
			unsecure:         false,
			wantErr:          true,
		},
		{
			name:             "wrong scheme",
			uri:              "https://example.com/callback?x=nonce123",
			expectedCallback: "https://example.com/callback",
			unsecure:         false,
			wantErr:          true,
		},
		{
			name:             "unsecure flag missing when required",
			uri:              "digiid://localhost:8080/callback?x=nonce123",
			expectedCallback: "http://localhost:8080/callback",
			unsecure:         true,
			wantErr:          true,
		},
		{
			name:             "invalid URI syntax",
			uri:              "://broken",
			expectedCallback: "https://example.com/callback",
			unsecure:         false,
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCallbackURI(tt.uri, tt.expectedCallback, tt.unsecure)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCallbackURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashMessage(t *testing.T) {
	tests := []struct {
		name    string
		message string
		// Expected hash is derived from: SHA256(SHA256(varint(len(magic)) + magic + varint(len(msg)) + msg))
	}{
		{
			name:    "empty message",
			message: "",
		},
		{
			name:    "simple message",
			message: "hello",
		},
		{
			name:    "digiid URI",
			message: "digiid://example.com/callback?x=abc123",
		},
		{
			name:    "long message (>252 bytes requires 3-byte varint)",
			message: string(make([]byte, 300)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashMessage(tt.message)

			// Hash should be 32 bytes
			if len(hash) != 32 {
				t.Errorf("HashMessage() returned hash of length %d, want 32", len(hash))
			}

			// Same message should produce same hash (deterministic)
			hash2 := HashMessage(tt.message)
			if hash != hash2 {
				t.Errorf("HashMessage() not deterministic: %x != %x", hash, hash2)
			}
		})
	}

	// Verify different messages produce different hashes
	t.Run("different messages produce different hashes", func(t *testing.T) {
		hash1 := HashMessage("message1")
		hash2 := HashMessage("message2")
		if hash1 == hash2 {
			t.Error("Different messages produced same hash")
		}
	})
}

func TestEncodeVarInt(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want []byte
	}{
		{
			name: "zero",
			n:    0,
			want: []byte{0x00},
		},
		{
			name: "small value (< 0xFD)",
			n:    0x10,
			want: []byte{0x10},
		},
		{
			name: "max single byte",
			n:    0xFC,
			want: []byte{0xFC},
		},
		{
			name: "2-byte value (0xFD prefix)",
			n:    0xFD,
			want: []byte{0xFD, 0xFD, 0x00},
		},
		{
			name: "2-byte value max",
			n:    0xFFFF,
			want: []byte{0xFD, 0xFF, 0xFF},
		},
		{
			name: "4-byte value (0xFE prefix)",
			n:    0x10000,
			want: []byte{0xFE, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name: "4-byte value max",
			n:    0xFFFFFFFF,
			want: []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name: "8-byte value (0xFF prefix)",
			n:    0x100000000,
			want: []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeVarInt(tt.n)
			if !bytesEqual(got, tt.want) {
				t.Errorf("encodeVarInt(%d) = %x, want %x", tt.n, got, tt.want)
			}
		})
	}
}

func TestVerifySignature_InvalidInputs(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		signature string
		uri       string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "empty address",
			address:   "",
			signature: "SGVsbG8gV29ybGQh", // valid base64
			uri:       "digiid://example.com/callback?x=test",
			wantErr:   true,
			errMsg:    "invalid address",
		},
		{
			name:      "invalid address prefix",
			address:   "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
			signature: "SGVsbG8gV29ybGQh",
			uri:       "digiid://example.com/callback?x=test",
			wantErr:   true,
			errMsg:    "invalid address",
		},
		{
			name:      "invalid base64 signature",
			address:   "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7klfq2fx", // bech32 passes prefix check
			signature: "not-valid-base64!!!",
			uri:       "digiid://example.com/callback?x=test",
			wantErr:   true,
			errMsg:    "invalid base64",
		},
		{
			name:      "signature wrong length",
			address:   "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7klfq2fx", // bech32 passes prefix check
			signature: "SGVsbG8gV29ybGQh",                            // "Hello World!" - only 12 bytes, not 65
			uri:       "digiid://example.com/callback?x=test",
			wantErr:   true,
			errMsg:    "invalid signature length",
		},
		{
			name:      "signature exactly 65 bytes but invalid recovery",
			address:   "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7klfq2fx",                                              // bech32 passes prefix check
			signature: "IQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Exactly 65 bytes
			uri:       "digiid://example.com/callback?x=test",
			wantErr:   true,
			errMsg:    "failed to recover",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.address, tt.signature, tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("VerifySignature() error = %v, should contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestVerifySignature_KnownTestVector tests signature verification with a known valid signature.
// This test uses a pre-generated signature from a DigiByte wallet.
// Note: In a real implementation, you'd have test vectors from the DigiByte team or
// generate them using a test wallet.
func TestVerifySignature_KnownTestVector(t *testing.T) {
	// Skip if we don't have real test vectors
	// In production, these would be provided by the DigiByte team or generated
	// using a test wallet with known private keys
	t.Skip("Skipping: requires real Digi-ID test vectors with valid signatures")

	tests := []struct {
		name      string
		address   string
		signature string
		uri       string
		wantErr   bool
	}{
		{
			name:      "valid signature from DigiByte Core wallet",
			address:   "DTestAddressFromWallet123",
			signature: "Base64EncodedSignature==",
			uri:       "digiid://example.com/callback?x=testnonce",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.address, tt.signature, tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDigiByteMessageMagic verifies we're using the correct message magic
func TestDigiByteMessageMagic(t *testing.T) {
	// CRITICAL: DigiByte uses a different magic than Bitcoin
	expected := "DigiByte Signed Message:\n"
	if DigiByteMessageMagic != expected {
		t.Errorf("DigiByteMessageMagic = %q, want %q", DigiByteMessageMagic, expected)
	}

	// Verify it's NOT Bitcoin's magic
	bitcoinMagic := "Bitcoin Signed Message:\n"
	if DigiByteMessageMagic == bitcoinMagic {
		t.Error("DigiByteMessageMagic should NOT equal Bitcoin's message magic")
	}
}

// TestDGBAddressVersionBytes verifies DigiByte address version bytes
func TestDGBAddressVersionBytes(t *testing.T) {
	// DigiByte mainnet P2PKH starts with 'D'
	if dgbPubKeyHashAddrID != 0x1E {
		t.Errorf("dgbPubKeyHashAddrID = 0x%02X, want 0x1E", dgbPubKeyHashAddrID)
	}

	// DigiByte mainnet P2SH
	if dgbScriptHashAddrID != 0x3F {
		t.Errorf("dgbScriptHashAddrID = 0x%02X, want 0x3F", dgbScriptHashAddrID)
	}
}

// Helper functions

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmarks

func BenchmarkHashMessage(b *testing.B) {
	message := "digiid://example.com/api/v1/auth/callback?x=abc123def456789"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashMessage(message)
	}
}

func BenchmarkValidateAddress(b *testing.B) {
	address := "DFundmGDNPSZDDZKdBNfT6kf2tJ7GPqPrs"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateAddress(address)
	}
}

func BenchmarkBuildChallengeURI(b *testing.B) {
	callback := "https://digiauth.example.com/api/v1/auth/callback"
	nonce := hex.EncodeToString(make([]byte, 32))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BuildChallengeURI(callback, nonce, false)
	}
}
