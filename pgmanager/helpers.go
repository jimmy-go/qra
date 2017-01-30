// Package pgmanager contains a QRA manager for PostgreSQL.
//
// MIT License
//
// Copyright (c) 2016 Angel Del Castillo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package pgmanager

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/ascii85"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/jimmy-go/qra"

	"golang.org/x/crypto/bcrypt"
)

// meID returns the identity id from database.
func meID(me string) (string, error) {
	var s string
	err := Db.Get(&s, `
		SELECT id FROM identity WHERE name=$1;
	`, me)
	if err != nil {
		return "", err
	}
	return s, nil
}

// meHimID returns the identities id from database in order: me.id, him.id
func meHimID(me, him string) (string, string, error) {
	var us []struct {
		ID   string `db:"id"`
		Name string `db:"name"`
	}
	err := Db.Select(&us, `
		SELECT id,name FROM identity WHERE name=$1 OR name=$2;
	`, me, him)
	if err != nil {
		return "", "", err
	}

	if len(us) != 2 {
		return "", "", errors.New("identity source and target not found")
	}

	var meID, himID string
	if us[0].Name == me {
		meID, himID = us[0].ID, us[1].ID
	} else {
		meID, himID = us[1].ID, us[0].ID
	}
	return meID, himID, nil
}

// generateSignature takes the x509 private key and sign data.
func generateSignature(privateKey, data []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return []byte{}, errors.New("invalid input")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, err
	}

	h := sha256.New()
	_, err = h.Write(data)
	if err != nil {
		log.Printf("generateSignature : write hash : err [%s]", err)
	}
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(cryptorand.Reader, privKey, crypto.SHA256, digest)
	if err != nil {
		return []byte{}, err
	}
	return s, nil
}

// createCertAndSecret generates a x509 cert and returns the
// public key and private key.
func createCertAndSecret(identity, hosts string) ([]byte, []byte, error) {

	// generate private key

	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 256)
	serialNumber, err := cryptorand.Int(cryptorand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	cr := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"QRA"},
			CommonName:   identity,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour * 365 * 2),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hs := strings.Split(hosts, ",")
	for _, h := range hs {
		if ip := net.ParseIP(h); ip != nil {
			cr.IPAddresses = append(cr.IPAddresses, ip)
		} else {
			cr.DNSNames = append(cr.DNSNames, h)
		}
	}

	// generate cert

	certBytes, err := x509.CreateCertificate(cryptorand.Reader, &cr, &cr, priv.Public(), priv)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	publicKeyBuf := bytes.NewBuffer([]byte{})
	err = pem.Encode(publicKeyBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return []byte{}, []byte{}, err
	}

	privateKeyBuf := bytes.NewBuffer([]byte{})
	err = pem.Encode(privateKeyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return publicKeyBuf.Bytes(), privateKeyBuf.Bytes(), nil
}

// AESCBCDecrypt decrypts cipher text using AES CBC mode.
func AESCBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	// FIXME; validate key size. add padding or check another solution.
	if len(key) < 32 {
		for i := len(key); i < 32; i++ {
			key = append(key, []byte(" ")...)
		}
	}
	if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return []byte{}, errors.New("invalid size")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return []byte{}, errors.New("invalid size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return ciphertext, nil
}

// AESCBCEncrypt encrypts using AES CBC mode.
// FIXME; padding plaintext and key.
func AESCBCEncrypt(key, plaintext []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	l := len(plaintext)
	size := int(l / aes.BlockSize)
	mustSize := size*aes.BlockSize + aes.BlockSize

	// generate padding

	if l < mustSize {
		for i := l; i < mustSize; i++ {
			plaintext = append(plaintext, []byte(" ")...)
		}
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return []byte{}, errors.New("invalid block size")
	}

	// FIXME; validate key size. add padding or check another solution.

	if len(key) < 32 {
		for i := len(key); i < 32; i++ {
			key = append(key, []byte(" ")...)
		}
	}
	if len(key) > 32 {
		key = key[:32]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(cryptorand.Reader, iv); err != nil {
		return []byte{}, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// makeUser makes a user with password and returns ID.
func makeUser(username, password string) (string, error) {
	if len(password) < PassMin {
		return "", qra.ErrPasswordSize
	}
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// generate x509 private key and public key.

	pubKey, privKey, err := createCertAndSecret(username, "localhost,127.0.0.1")
	if err != nil {
		return "", err
	}

	// encrypt private key with AES-CBC using raw password.

	ciphertext, err := AESCBCEncrypt([]byte(password), privKey)
	if err != nil {
		return "", err
	}

	// store identity

	var s string
	err = Db.Get(&s, `
		INSERT INTO identity
		(name,password,private_key,public_key)
		VALUES($1,$2,$3,$4)
		RETURNING id;
	`, username, passHash, ciphertext, pubKey)
	pubKey = nil
	privKey = nil
	passHash = nil
	ciphertext = nil
	return s, err
}

// MakePassword generates a random password of l length.
func MakePassword(l int) (string, error) {
	if l < 10 {
		return "", errors.New("password lenght must be greater than 10 chars")
	}
	bb := make([]byte, l)
	_, err := cryptorand.Read(bb)
	if err != nil {
		return "", err
	}
	b := make([]byte, ascii85.MaxEncodedLen(len(bb)))
	ascii85.Encode(b, bb)
	return string(b)[:l], nil
}
