# go-encrypt
Encryption and Hash Library for GoLang

Due to Data At Rest Encryption requirements, as developers,
we frequently use encryption, decryption and hashing functions.

I have gathered the functions, I have used in previous projects into one Library.
These are expected to be used with a database transactions.

General Rules:
- User data should always be encrypted.
- Password should always be hashed.

I usually follow encrypt everything if possible,
avoid storing personal user data if possible.

Hash usage:

```go
hasher, err := encrypt.New()
if err != nil {
  return err
}
hash, err := hasher.Hash([]byte("my password"))
if err != nil {
  return err
}
```

Encryption usage:

```go
passphrase := "my-secret-passphrase"
encryptor, err := encrypt.New(encrypt.WithPassphraseText(passphrase))
if err != nil {
  return err
}

data := []byte("some data")
encryptedData, err := encryptor.Encrypt(data)
if err != nil {
  return err
}
```

If you use Passphrase as Text, it is hashed with sha256.
You can use your own longer passphrase as byte array using WithPassphrase option


Decryption usage:

```go
passphrase := "my-secret-passphrase"
encryptor, err := encrypt.New(encrypt.WithPassphraseText(passphrase))
if err != nil {
  return err
}

encryptedData := ... // Use the previous example
decryptedData, err := encryptor.Decrypt(encryptedData)
if err != nil {
  return err
}
```

##### Notes:
* Always use a long Passphrase different than default.
* In password hashing, you can follow encrypt password -> hash -> encrypt before storing.
