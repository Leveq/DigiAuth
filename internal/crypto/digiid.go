// Package crypto implements DigiByte Digi-ID signature verification.
//
// The Digi-ID protocol uses the same message signing scheme as Bitcoin's
// "signmessage" RPC, but with "DigiByte Signed Message:\n" as the magic prefix.
//
// Flow:
//  1. Server generates a challenge URI: digiid://callback?x=nonce
//  2. Wallet signs the URI using the private key for a DGB address
//  3. Server verifies the signature matches the claimed address
//
// The signature is base64-encoded compact ECDSA (65 bytes: 1 recovery + 32 R + 32 S).
// Verification recovers the public key from the signature, derives the address,
// and checks it matches the claimed address.
package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	// DigiByteMessageMagic is the prefix used by DigiByte wallets when signing messages.
	// This differs from Bitcoin's "Bitcoin Signed Message:\n".
	DigiByteMessageMagic = "DigiByte Signed Message:\n"

	// DigiIDScheme is the URI scheme that triggers DigiByte wallets.
	DigiIDScheme = "digiid"

	// DGB mainnet address version bytes
	dgbPubKeyHashAddrID = 0x1E // 'D' prefix for mainnet P2PKH addresses
	dgbScriptHashAddrID = 0x3F // Mainnet P2SH
)

// dgbMainNetParams defines DigiByte mainnet parameters for address decoding.
// DigiByte uses different version bytes than Bitcoin.
var dgbMainNetParams = chaincfg.Params{
	Name: "dgb-mainnet",
	Net:  wire.MainNet,

	PubKeyHashAddrID: dgbPubKeyHashAddrID,
	ScriptHashAddrID: dgbScriptHashAddrID,
}

// VerifySignature verifies a Digi-ID signature against a DigiByte address and message URI.
//
// Parameters:
//   - address: The DigiByte address that allegedly signed the message (base58check encoded)
//   - signature: Base64-encoded compact ECDSA signature (65 bytes)
//   - uri: The digiid:// URI that was signed (the challenge)
//
// Returns nil if the signature is valid, or an error describing why verification failed.
func VerifySignature(address, signature, uri string) error {
	// 1. Validate the address format
	if err := ValidateAddress(address); err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	// 2. Decode the base64 signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(sigBytes))
	}

	// 3. Compute the message hash using DigiByte's message magic
	messageHash := HashMessage(uri)

	// 4. Recover the public key from the compact signature
	pubKey, wasCompressed, err := ecdsa.RecoverCompact(sigBytes, messageHash[:])
	if err != nil {
		return fmt.Errorf("failed to recover public key: %w", err)
	}

	// 5. Derive the address from the recovered public key
	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pubKey.SerializeCompressed()
	} else {
		serializedPubKey = pubKey.SerializeUncompressed()
	}

	// Hash the public key to get the address (RIPEMD160(SHA256(pubkey)))
	recoveredAddr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(serializedPubKey),
		&dgbMainNetParams,
	)
	if err != nil {
		return fmt.Errorf("failed to derive address from recovered key: %w", err)
	}

	// 6. Compare the recovered address with the claimed address
	if recoveredAddr.EncodeAddress() != address {
		return fmt.Errorf("signature verification failed: recovered address %s does not match claimed address %s",
			recoveredAddr.EncodeAddress(), address)
	}

	return nil
}

// HashMessage computes the double-SHA256 hash of a message using DigiByte's
// message signing format: varint(len(magic)) + magic + varint(len(message)) + message
func HashMessage(message string) chainhash.Hash {
	var buf []byte

	// Prepend the magic prefix with its length as a varint
	buf = append(buf, byte(len(DigiByteMessageMagic)))
	buf = append(buf, []byte(DigiByteMessageMagic)...)

	// Append the message with its length as a varint
	msgBytes := []byte(message)
	buf = append(buf, encodeVarInt(uint64(len(msgBytes)))...)
	buf = append(buf, msgBytes...)

	// Double SHA-256
	first := sha256.Sum256(buf)
	return sha256.Sum256(first[:])
}

// ValidateAddress checks if a string is a valid DigiByte mainnet address.
func ValidateAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address is empty")
	}

	// DigiByte mainnet P2PKH addresses start with 'D' and are typically 34 chars
	// DigiByte also supports 'S' prefix for P2SH and 'dgb1' for bech32
	if !strings.HasPrefix(address, "D") && !strings.HasPrefix(address, "S") && !strings.HasPrefix(address, "dgb1") {
		return fmt.Errorf("invalid DigiByte address prefix: must start with D, S, or dgb1")
	}

	// For legacy addresses, verify the base58check encoding
	if strings.HasPrefix(address, "D") || strings.HasPrefix(address, "S") {
		_, err := btcutil.DecodeAddress(address, &dgbMainNetParams)
		if err != nil {
			return fmt.Errorf("invalid base58check encoding: %w", err)
		}
	}

	// TODO: Add bech32 validation for dgb1 addresses when needed

	return nil
}

// BuildChallengeURI constructs a Digi-ID challenge URI.
//
// Format: digiid://callback_host/callback_path?x=nonce[&u=1]
//
// Parameters:
//   - callbackURL: Full callback URL (e.g., "https://digiauth.leveq.dev/api/v1/auth/callback")
//   - nonce: Unique random string tied to the user's session
//   - unsecure: If true, appends &u=1 to indicate HTTP callback (dev only)
func BuildChallengeURI(callbackURL, nonce string, unsecure bool) (string, error) {
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("invalid callback URL: %w", err)
	}

	// Strip the scheme — digiid:// replaces http(s)://
	host := parsed.Host
	path := parsed.Path

	// Build the digiid URI
	uri := fmt.Sprintf("%s://%s%s?x=%s", DigiIDScheme, host, path, nonce)
	if unsecure {
		uri += "&u=1"
	}

	return uri, nil
}

// ExtractNonce pulls the nonce (x parameter) from a Digi-ID URI.
func ExtractNonce(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid URI: %w", err)
	}

	nonce := parsed.Query().Get("x")
	if nonce == "" {
		return "", fmt.Errorf("nonce (x parameter) not found in URI")
	}

	return nonce, nil
}

// ValidateCallbackURI checks that a Digi-ID URI matches the expected callback.
func ValidateCallbackURI(uri, expectedCallbackURL string, unsecure bool) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	if parsed.Scheme != DigiIDScheme {
		return fmt.Errorf("invalid scheme: expected %s, got %s", DigiIDScheme, parsed.Scheme)
	}

	// Reconstruct what the callback should look like
	expectedParsed, err := url.Parse(expectedCallbackURL)
	if err != nil {
		return fmt.Errorf("invalid expected callback URL: %w", err)
	}

	if parsed.Host != expectedParsed.Host {
		return fmt.Errorf("host mismatch: expected %s, got %s", expectedParsed.Host, parsed.Host)
	}

	if parsed.Path != expectedParsed.Path {
		return fmt.Errorf("path mismatch: expected %s, got %s", expectedParsed.Path, parsed.Path)
	}

	// Check unsecure flag
	if unsecure && parsed.Query().Get("u") != "1" {
		return fmt.Errorf("unsecure flag mismatch")
	}

	return nil
}

// encodeVarInt encodes a uint64 as a Bitcoin-style variable-length integer.
func encodeVarInt(n uint64) []byte {
	if n < 0xFD {
		return []byte{byte(n)}
	}
	if n <= 0xFFFF {
		buf := make([]byte, 3)
		buf[0] = 0xFD
		buf[1] = byte(n)
		buf[2] = byte(n >> 8)
		return buf
	}
	if n <= 0xFFFFFFFF {
		buf := make([]byte, 5)
		buf[0] = 0xFE
		buf[1] = byte(n)
		buf[2] = byte(n >> 8)
		buf[3] = byte(n >> 16)
		buf[4] = byte(n >> 24)
		return buf
	}
	buf := make([]byte, 9)
	buf[0] = 0xFF
	buf[1] = byte(n)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n >> 16)
	buf[4] = byte(n >> 24)
	buf[5] = byte(n >> 32)
	buf[6] = byte(n >> 40)
	buf[7] = byte(n >> 48)
	buf[8] = byte(n >> 56)
	return buf
}
