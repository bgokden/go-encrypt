package encrypt_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bgokden/go-encrypt/encrypt"
)

func TestHash(t *testing.T) {
	hasher, err := encrypt.New()
	assert.Nil(t, err)

	hash, err := hasher.Hash([]byte("my password"))
	assert.Nil(t, err)

	resultSame, err := hasher.Compare([]byte("my password"), hash)
	assert.Nil(t, err)
	assert.Equal(t, true, resultSame)

	resultDifferent, err := hasher.Compare([]byte("not my password"), hash)
	assert.Nil(t, err)
	assert.Equal(t, false, resultDifferent)
}

func TestEncryptDecrypt(t *testing.T) {
	passphrase := "my-secret-passphrase"
	encryptor, err := encrypt.New(encrypt.WithPassphraseText(passphrase))
	assert.Nil(t, err)

	data := []byte("some data")
	encryptedData, err := encryptor.Encrypt(data)

	assert.Nil(t, err)

	decryptedData, err := encryptor.Decrypt(encryptedData)

	assert.Nil(t, err)
	assert.Equal(t, data, decryptedData)
}
