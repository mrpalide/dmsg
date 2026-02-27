// Package noise pkg/noise/noise.go
package noise

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/skycoin/noise"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/cipher"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/logging"
)

var noiseLogger = logging.MustGetLogger("noise")

// ErrInvalidCipherText occurs when a ciphertext is received which is too short in size.
var ErrInvalidCipherText = errors.New("noise decrypt unsafe: ciphertext cannot be less than 8 bytes")

// nonceSize is the noise cipher state's nonce size in bytes.
const nonceSize = 8

// Config hold noise parameters.
type Config struct {
	LocalPK   cipher.PubKey // Local instance static public key.
	LocalSK   cipher.SecKey // Local instance static secret key.
	RemotePK  cipher.PubKey // Remote instance static public key.
	Initiator bool          // Whether the local instance initiates the connection.
}

// Noise handles the handshake and the frame's cryptography.
// All operations on Noise are not guaranteed to be thread-safe.
type Noise struct {
	pk   cipher.PubKey
	sk   cipher.SecKey
	init bool

	pattern noise.HandshakePattern
	hs      *noise.HandshakeState
	enc     *noise.CipherState
	dec     *noise.CipherState

	encNonce uint64 // increment after encryption
	decNonce uint64 // expect increment with each subsequent packet
}

// New creates a new Noise with:
//   - provided pattern for handshake.
//   - Secp256k1 for the curve.
func New(pattern noise.HandshakePattern, config Config) (*Noise, error) {
	nc := noise.Config{
		CipherSuite: noise.NewCipherSuite(Secp256k1{}, noise.CipherChaChaPoly, noise.HashSHA256),
		Random:      rand.Reader,
		Pattern:     pattern,
		Initiator:   config.Initiator,
		StaticKeypair: noise.DHKey{
			Public:  config.LocalPK[:],
			Private: config.LocalSK[:],
		},
	}
	if !config.RemotePK.Null() {
		nc.PeerStatic = config.RemotePK[:]
	}

	hs, err := noise.NewHandshakeState(nc)
	if err != nil {
		return nil, err
	}
	return &Noise{
		pk:      config.LocalPK,
		sk:      config.LocalSK,
		init:    config.Initiator,
		pattern: pattern,
		hs:      hs,
	}, nil
}

// KKAndSecp256k1 creates a new Noise with:
//   - KK pattern for handshake.
//   - Secp256k1 for the curve.
func KKAndSecp256k1(config Config) (*Noise, error) {
	return New(noise.HandshakeKK, config)
}

// XKAndSecp256k1 creates a new Noise with:
//   - XK pattern for handshake.
//   - Secp256 for the curve.
func XKAndSecp256k1(config Config) (*Noise, error) {
	return New(noise.HandshakeXK, config)
}

// GetEncNonce returns underlying encNonce.
func (ns *Noise) GetEncNonce() uint64 {
	return ns.encNonce
}

// GetDecNonce returns underlying decNonce.
func (ns *Noise) GetDecNonce() uint64 {
	return ns.decNonce
}

// MakeHandshakeMessage generates handshake message for a current handshake state.
func (ns *Noise) MakeHandshakeMessage() (res []byte, err error) {
	if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
		res, _, _, err = ns.hs.WriteMessage(nil, nil)
		return
	}

	res, ns.dec, ns.enc, err = ns.hs.WriteMessage(nil, nil)
	return res, err
}

// ProcessHandshakeMessage processes a received handshake message and appends the payload.
func (ns *Noise) ProcessHandshakeMessage(msg []byte) (err error) {
	if ns.hs.MessageIndex() < len(ns.pattern.Messages)-1 {
		_, _, _, err = ns.hs.ReadMessage(nil, msg)
		return
	}

	_, ns.enc, ns.dec, err = ns.hs.ReadMessage(nil, msg)
	return err
}

// HandshakeFinished indicate whether handshake was completed.
func (ns *Noise) HandshakeFinished() bool {
	return ns.hs.MessageIndex() == len(ns.pattern.Messages)
}

// LocalStatic returns the local static public key.
func (ns *Noise) LocalStatic() cipher.PubKey {
	return ns.pk
}

// RemoteStatic returns the remote static public key.
func (ns *Noise) RemoteStatic() cipher.PubKey {
	pk, err := cipher.NewPubKey(ns.hs.PeerStatic())
	if err != nil {
		panic(err)
	}
	return pk
}

// EncryptUnsafe encrypts plaintext without interlocking, should only
// be used with external lock.
func (ns *Noise) EncryptUnsafe(plaintext []byte) []byte {
	ns.encNonce++
	buf := make([]byte, nonceSize)
	binary.BigEndian.PutUint64(buf, ns.encNonce)
	return append(buf, ns.enc.Cipher().Encrypt(nil, ns.encNonce, nil, plaintext)...)
}

// DecryptUnsafe decrypts ciphertext without interlocking, should only
// be used with external lock.
func (ns *Noise) DecryptUnsafe(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCipherText
	}
	recvSeq := binary.BigEndian.Uint64(ciphertext[:nonceSize])
	if recvSeq <= ns.decNonce {
		return nil, fmt.Errorf("received decryption nonce (%d) is not larger than previous (%d)", recvSeq, ns.decNonce)
	}
	ns.decNonce = recvSeq
	return ns.dec.Cipher().Decrypt(nil, recvSeq, nil, ciphertext[nonceSize:])
}

// NonceMap is a map of used nonces.
type NonceMap map[uint64]struct{}

// DecryptWithNonceMap is equivalent to DecryptNonce, instead it uses NonceMap to track nonces instead of a counter.
func (ns *Noise) DecryptWithNonceMap(nm NonceMap, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCipherText
	}
	recvSeq := binary.BigEndian.Uint64(ciphertext[:nonceSize])
	if _, ok := nm[recvSeq]; ok {
		return nil, fmt.Errorf("received decryption nonce (%d) is repeated", recvSeq)
	}
	return ns.dec.Cipher().Decrypt(nil, recvSeq, nil, ciphertext[nonceSize:])
}

// GetCipherKeys extracts the derived cipher keys from a completed Noise handshake.
// This should only be called after HandshakeFinished() returns true.
// Returns (encKey, decKey, error) where each key is 32 bytes.
// Uses reflection to access private key fields in noise.CipherState.
func (ns *Noise) GetCipherKeys() ([]byte, []byte, error) {
	if ns.enc == nil || ns.dec == nil {
		return nil, nil, errors.New("handshake not completed")
	}

	// Use reflection to access the private 'k' field ([32]byte key)
	encKey := extractCipherStateKey(ns.enc)
	decKey := extractCipherStateKey(ns.dec)

	if len(encKey) != 32 || len(decKey) != 32 {
		return nil, nil, fmt.Errorf("invalid cipher key length: enc=%d, dec=%d", len(encKey), len(decKey))
	}

	// Return copies to prevent mutation
	return append([]byte(nil), encKey...), append([]byte(nil), decKey...), nil
}

// NewNoiseFromCachedKeys creates a Noise instance from cached cipher keys.
// This skips the expensive ECDH handshake by reusing previously derived keys.
// Nonces are always reset to 0 for each new connection (critical for security).
func NewNoiseFromCachedKeys(config Config, encKey, decKey []byte) (*Noise, error) {
	if len(encKey) != 32 || len(decKey) != 32 {
		return nil, fmt.Errorf("invalid cipher key length: enc=%d, dec=%d (expected 32)", len(encKey), len(decKey))
	}

	// Create a temporary Noise instance to get the cipher suite
	nc := noise.Config{
		CipherSuite: noise.NewCipherSuite(Secp256k1{}, noise.CipherChaChaPoly, noise.HashSHA256),
		Random:      rand.Reader,
		Pattern:     noise.HandshakeKK,
		Initiator:   config.Initiator,
		StaticKeypair: noise.DHKey{
			Public:  config.LocalPK[:],
			Private: config.LocalSK[:],
		},
	}

	// Create cipher states with the cached keys
	cs := nc.CipherSuite

	// Convert []byte to [32]byte for Cipher() method
	var encKeyArray, decKeyArray [32]byte
	copy(encKeyArray[:], encKey)
	copy(decKeyArray[:], decKey)

	encCipher := cs.Cipher(encKeyArray)
	decCipher := cs.Cipher(decKeyArray)

	encState := &noise.CipherState{}
	decState := &noise.CipherState{}

	// Use reflection to set private fields
	setCipherStateFields(encState, cs, encCipher, encKey)
	setCipherStateFields(decState, cs, decCipher, decKey)

	return &Noise{
		pk:       config.LocalPK,
		sk:       config.LocalSK,
		init:     config.Initiator,
		pattern:  noise.HandshakeKK, // Always KK for cached sessions
		hs:       nil,                // No handshake state needed
		enc:      encState,
		dec:      decState,
		encNonce: 0, // Always start at 0 for new connection
		decNonce: 0, // Always start at 0 for new connection
	}, nil
}

// extractCipherStateKey uses reflection to extract the private 'k' field from noise.CipherState.
// CipherState structure: {cs CipherSuite, c Cipher, k [32]byte, n uint64}
func extractCipherStateKey(cs *noise.CipherState) []byte {
	if cs == nil {
		return nil
	}

	// Use reflection to access the private 'k' field
	csValue := reflect.ValueOf(cs).Elem()
	kField := csValue.FieldByName("k")

	if !kField.IsValid() {
		noiseLogger.Error("Failed to access CipherState 'k' field")
		return nil
	}

	// Get the [32]byte array
	var key [32]byte

	// Use unsafe to read the private field
	kFieldPtr := unsafe.Pointer(kField.UnsafeAddr())
	key = *(*[32]byte)(kFieldPtr)

	return key[:]
}

// setCipherStateFields uses reflection to set private fields in noise.CipherState.
// This is needed to create a CipherState from cached keys without going through handshake.
func setCipherStateFields(cs *noise.CipherState, cipherSuite noise.CipherSuite, cipher noise.Cipher, key []byte) {
	if cs == nil || len(key) != 32 {
		return
	}

	csValue := reflect.ValueOf(cs).Elem()

	// Set 'cs' field (CipherSuite)
	csField := csValue.FieldByName("cs")
	if csField.IsValid() {
		reflect.NewAt(csField.Type(), unsafe.Pointer(csField.UnsafeAddr())).
			Elem().Set(reflect.ValueOf(cipherSuite))
	}

	// Set 'c' field (Cipher)
	cField := csValue.FieldByName("c")
	if cField.IsValid() {
		reflect.NewAt(cField.Type(), unsafe.Pointer(cField.UnsafeAddr())).
			Elem().Set(reflect.ValueOf(cipher))
	}

	// Set 'k' field ([32]byte key)
	kField := csValue.FieldByName("k")
	if kField.IsValid() {
		var keyArray [32]byte
		copy(keyArray[:], key)
		kFieldPtr := unsafe.Pointer(kField.UnsafeAddr())
		*(*[32]byte)(kFieldPtr) = keyArray
	}

	// Set 'n' field (nonce counter) to 0
	nField := csValue.FieldByName("n")
	if nField.IsValid() {
		reflect.NewAt(nField.Type(), unsafe.Pointer(nField.UnsafeAddr())).
			Elem().SetUint(0)
	}
}
