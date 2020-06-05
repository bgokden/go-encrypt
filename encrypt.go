package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	CIPHER_KEY_LEN = 32
	SALT_KEY_LEN   = 32
)

// Hasher represent the interface to use one-way hash
type Hasher interface {
	Hash([]byte) ([]byte, error)
	Compare([]byte, []byte) (bool, error)
}

// Encryptor encrypts data
type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
}

// Decryptor decrypts encrypted data
type Decryptor interface {
	Decrypt([]byte) ([]byte, error)
}

// EncryptTool implements Hasher, Encryptor and Decryptor
type EncryptTool struct {
	Passphrase []byte
	Time       uint32
	Memory     uint32
	Threads    uint8
	KeyLen     uint32
}

// EncryptToolOption allows you to define options
type EncryptToolOption func(*EncryptTool)

// WithPassphraseText option sets sha256 hash of passphrase as encryption key
func WithPassphraseText(passphrase string) EncryptToolOption {
	return func(e *EncryptTool) {
		e.Passphrase = Sha256Hash(passphrase)
	}
}

// WithPassphrase option sets passphrase as encryption key
func WithPassphrase(passphrase []byte) EncryptToolOption {
	return func(e *EncryptTool) {
		e.Passphrase = passphrase
	}
}

// WithTime option set argon2id time
func WithTime(time uint32) EncryptToolOption {
	return func(e *EncryptTool) {
		e.Time = time
	}
}

// WithMemory option set argon2id memory
func WithMemory(memory uint32) EncryptToolOption {
	return func(e *EncryptTool) {
		e.Memory = memory
	}
}

// WithThreads option set argon2id threads
func WithThreads(threads uint8) EncryptToolOption {
	return func(e *EncryptTool) {
		e.Threads = threads
	}
}

// WithKeyLen option set argon2id key Length
func WithKeyLen(keyLen uint32) EncryptToolOption {
	return func(e *EncryptTool) {
		e.KeyLen = keyLen
	}
}

// New created a Encryptor/Decryptor/Hasher object with given options
func New(opts ...EncryptToolOption) (*EncryptTool, error) {
	const (
		defaultPassphraseText = "my-super-secret-passphrase"
		defaultTime           = 1
		defaultMemory         = 64 * 1024
		defaultThreads        = 4
		defaultKeyLen         = 32
	)

	e := &EncryptTool{
		Passphrase: Sha256Hash(defaultPassphraseText),
		Time:       defaultTime,
		Memory:     defaultMemory,
		Threads:    defaultThreads,
		KeyLen:     defaultKeyLen,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e, nil
}

// Sha256Hash utility tool
func Sha256Hash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

// Encrypt encrypts given data
func (e *EncryptTool) Encrypt(data []byte) ([]byte, error) {
	key, salt, err := e.DeriveKey(nil)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

// Decrypt decrypts given data
func (e *EncryptTool) Decrypt(data []byte) ([]byte, error) {
	if len(data) < CIPHER_KEY_LEN {
		return nil, errors.New("Invalid Input")
	}
	salt, data := data[len(data)-CIPHER_KEY_LEN:], data[:len(data)-CIPHER_KEY_LEN]
	key, _, err := e.DeriveKey(salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Hash hashes given data with argon2id
func (e *EncryptTool) Hash(data []byte) ([]byte, error) {
	salt := make([]byte, SALT_KEY_LEN)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := argon2.IDKey(data, salt, e.Time, e.Memory, e.Threads, e.KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	full := fmt.Sprintf(format, argon2.Version, e.Memory, e.Time, e.Threads, b64Salt, b64Hash)
	return []byte(full), nil
}

// Compare compares data which is hashed with Hash
func (e *EncryptTool) Compare(data, hash []byte) (bool, error) {
	parts := strings.Split(string(hash), "$")

	var memory uint32
	var time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	keyLen := uint32(len(decodedHash))

	comparisonHash := argon2.IDKey(data, salt, time, memory, threads, keyLen)

	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1), nil
}

// DeriveKey generates a key based on passphrase and salt if given
func (e *EncryptTool) DeriveKey(salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, SALT_KEY_LEN)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key := argon2.IDKey(e.Passphrase, salt, e.Time, e.Memory, e.Threads, CIPHER_KEY_LEN)
	return key, salt, nil
}
