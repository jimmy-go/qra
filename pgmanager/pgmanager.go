// Package pgmanager contains the Default manager for roles,
// sessions, user permissions and users itself in SQLite.
//
// You can use it as current state or make your own satisfying
// qra.Manager interface.
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
	// import driver in main
	// _ "github.com/lib/pq"

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
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/jimmy-go/pgwp"
	"github.com/jimmy-go/qra"
	"github.com/satori/go.uuid"
)

var (
	authentication *Authenticationer
	designation    *Designationer

	// Db database for this manager.
	Db *pgwp.Pool

	errSystemNotFound        = errors.New("pgmanager: system identity not found")
	errPermissionNotFound    = errors.New("pgmanager: permission not found")
	errInvalidCredentials    = errors.New("pgmanager: invalid username or password")
	errResourceNotSpecified  = errors.New("pgmanager: resource not specified")
	errInvalidPasswordLength = errors.New("pgmanager: invalid password size")

	// ErrOwnSign error returned when an identity try to auto sign a permission.
	ErrOwnSign = errors.New("pgmanager: can't allow own permission")

	// ErrIdentityNotFound error returned when identity not exists in database.
	ErrIdentityNotFound = errors.New("pgmanager: identity not found")
)

const (
	// PermSessionOn permission for session on web, terminal or others that developer
	// want to implement.
	PermSessionOn = "session-on"
	// PermIdentityCreate  _
	PermIdentityCreate = "identity-create"
	// PermIdentityEdit _
	PermIdentityEdit = "identity-edit"
	// PermIdentityDelete _
	PermIdentityDelete = "identity-delete"
	// PermRead _
	PermRead = "read"
	// PermWrite _
	PermWrite = "write"
	// PermDelete _
	PermDelete = "delete"

	// MinPassLen defines the minimum of a password.
	MinPassLen = 8

	// System defines identity username for SYSTEM.
	System = "system"

	// SessionDuration defines the duration for a session on database.
	// default 3 months.
	SessionDuration = time.Duration(24 * time.Hour * 30 * 3)

	// PermissionDuration defines the duration default for a permission.
	// default 1 year.
	PermissionDuration = time.Duration(24 * time.Hour * 365 * 1)
)

// Connect starts the manager.
func Connect(driver, connectURL string, terminalSession bool) error {
	var err error
	Db, err = pgwp.Connect(driver, connectURL, 5, 5)
	if err != nil {
		return err
	}
	authentication = &Authenticationer{DB: Db}
	designation = &Designationer{DB: Db}

	qra.MustRegisterAuthentication(authentication)
	qra.MustRegisterDesignation(designation)
	err = systemCheck(terminalSession)
	if err != nil {
		return err
	}
	return nil
}

// systemCheck will verifies several things:
//		identity system exists.
//		system permission designation.
func systemCheck(terminalSession bool) error {
	var systemID string
	err := Db.Get(&systemID, `
		SELECT id FROM identity WHERE name=$1;
	`, System)
	if err != nil {
		log.Printf("system identity not found: creating system")

		// generate random password for "system".
		randpass := MakePassword(64)

		_, err = makeUser(System, randpass)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		ctx := &Context{
			Username: System,
		}

		// generate session

		err = authentication.Authenticate(ctx, randpass, &ctx.Token)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		// allow terminal session for identity "system"

		expiresAt := time.Now().UTC().Add(PermissionDuration)
		err = designation.Allow(ctx, randpass, PermSessionOn, "terminal", System, expiresAt)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		// allow create identity for user "system"

		err = designation.Allow(ctx, randpass, PermIdentityCreate, "*", System, expiresAt)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		// show once system password

		log.Printf("SYSTEM IDENTITY PASSWORD: %s", randpass)

		terminalSession = true
	}

	if terminalSession {
		Terminal()
	}
	return nil
}

// makeUser makes a user with password and returns ID.
func makeUser(username, password string) (string, error) {
	if len(password) < MinPassLen {
		return "", errInvalidPasswordLength
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

// Terminal starts an infinite loop to read the user's input.
func Terminal() {
	ost, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, ost)

	// create temporal file for log output

	f, err := os.OpenFile("qra_pgmanager.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Terminal : create temporal log : err [%s]", err)
		return
	}
	log.SetOutput(f)

	defer func() {
		f.Close()
		os.Remove(f.Name())

		// return log to stdout
		log.SetOutput(os.Stdout)
	}()

	// this represents user in terminal
	ctx := &Context{}

	term := terminal.NewTerminal(os.Stdin, "Help [:h]. Quit [:q]\n\rUsername:\n\r")
	for {
		l, err := term.ReadLine()
		if err != nil {
			log.Printf("Error read line : err [%s]", err)
			return
		}

		// prefix indicates action.
		var prefix string
		if len(l) > 1 {
			prefix = l[:2]
		}

		switch prefix {
		case ":q":
			return
		case "1:":
			x := strings.Split(l, ":")
			if len(x) != 2 {
				fmt.Printf("Write '1:identity'.\n\r")
				continue
			}

			buf := bytes.NewBuffer([]byte{})
			err = designation.Search(ctx, buf, "identity-create:*")
			if err != nil {
				log.Printf("search : err [%s]", err)
				fmt.Printf("You don't have 'identity-create' permission.\n\r")
				continue
			}

			p, err := term.ReadPassword("write password for the new identity\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password")
				continue
			}

			_, err = makeUser(x[1], p)
			if err != nil {
				log.Printf("can't create identity : err [%s]", err)
				fmt.Printf("Can't create identity. Password must be equal or greater than 8 characters\n\r")
				continue
			}
			fmt.Printf("New Identity created: %s\n\r", x[1])
			term.SetPrompt(ctx.Username + ":\n\r")
		case "2:":

			x := strings.Split(l, ":")
			log.Printf("x [%v]", x)
			if len(x) != 4 {
				fmt.Printf("Invalid format. Must be '2:identity:permission:resource'.\n\r")
				continue
			}

			p, err := term.ReadPassword("write identity password\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password : err [%s]", err)
				continue
			}

			// one month permission.
			expiresAt := time.Now().UTC().Add(24 * time.Hour * 30)

			err = designation.Allow(ctx, p, x[2], x[3], x[1], expiresAt)
			if err != nil {
				log.Printf("revoke : err [%s]", err)
				fmt.Printf("Can't share permission\n\r")
				continue
			}
			fmt.Printf("New permission shared\n\r")
			term.SetPrompt(ctx.Username + ":\n\r")
		case "3:":

			x := strings.Split(l, ":")
			log.Printf("x [%v]", x)
			if len(x) != 4 {
				fmt.Printf("Invalid format. Must be '3:identity:permission:resource'.\n\r")
				continue
			}

			p, err := term.ReadPassword("write identity password\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password : err [%s]", err)
				continue
			}

			err = designation.Revoke(ctx, p, x[2], x[3], x[1])
			if err != nil {
				log.Printf("revoke : err [%s]", err)
				fmt.Printf("Can't revoke permission\n\r")
				continue
			}
			fmt.Printf("permission removed\n\r")
			term.SetPrompt(ctx.Username + ":\n\r")
		case ":h":
			fmt.Printf("\n\rCreate identity (1:<Identity>)")
			fmt.Printf("\n\rShare permission (2:<Identity>:<Permission>:<Resource>)")
			fmt.Printf("\n\rRevoke permission (3:<Identity>:<Permission>:<Resource>)")
			fmt.Printf("\n\rLogout (5:)\n\r")
		case "5:", ":5":
			err := authentication.Close(ctx)
			if err != nil {
				fmt.Printf("Can't close session.\n\r")
				continue
			}
			fmt.Printf("Session closed.\n\r")
			term.SetPrompt("Help [:h]. Quit [:q]\n\rUsername:\n\r")
			ctx.Username = ""
			ctx.Token = ""
		default:

			// Login process.
			if len(ctx.Token) < 1 {
				if ctx.Username == "" && len(l) > 0 {
					ctx.Username = l

					p, err := term.ReadPassword("write password\n\r")
					if err != nil {
						fmt.Printf("can't read password : err [%s]", err)
						ctx.Username = ""
						continue
					}

					// authentication

					err = authentication.Authenticate(ctx, p, &ctx.Token)
					if err != nil {
						fmt.Printf("Invalid username or password\n\r")
						ctx.Username = ""
						continue
					}

					// session on terminal permission validation.

					buf := bytes.NewBuffer([]byte{})
					err = designation.Search(ctx, buf, "session-on:terminal")
					if err != nil {
						fmt.Printf("You don't have allowed terminal sessions\n\r")
						err = authentication.Close(ctx)
						if err != nil {
							log.Printf("Close session err [%s]", err)
						}
						ctx.Username = ""
						ctx.Token = ""
						continue
					}

					term.SetPrompt(ctx.Username + ":\n\r")
				}
			}
		}
	}
}

// Authenticationer struct
type Authenticationer struct {
	DB *pgwp.Pool
}

// IdentitySimple for identity retrieve.
type IdentitySimple struct {
	ID       string `db:"id"`
	Password []byte `db:"password"`
}

// Authenticate makes login for Identity.
func (s *Authenticationer) Authenticate(ctx qra.Identity, password string, dst interface{}) error {
	me := ctx.Me()
	log.Printf("Authenticate : username [%s] password [%s]", me, password)

	var u IdentitySimple
	err := s.DB.Get(&u, `
		SELECT id,password FROM identity WHERE name=$1;
	`, me)
	if err != nil {
		return err
	}
	// don't waste hashing time
	if len(u.Password) < 1 {
		return errInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword(u.Password, []byte(password))
	if err != nil {
		return errInvalidCredentials
	}

	expiresAt := time.Now().UTC().Add(SessionDuration)
	token := uuid.NewV4().String() + "." + uuid.NewV4().String()

	err = s.DB.Get(dst, `
		INSERT INTO session (identity_id,token,expires_at,active)
		VALUES ($1,$2,$3,$4)
		RETURNING token;
	`, u.ID, token, expiresAt, true)
	if err != nil {
		return err
	}
	return nil
}

// Close deletes current session of Identity.
func (s *Authenticationer) Close(ctx qra.Identity) error {
	me := ctx.Me()

	var sessionID string
	err := ctx.Session(&sessionID)
	if err != nil {
		log.Printf("Close : get session : err [%s]", err)
		return err
	}
	log.Printf("Close : username [%s] session id [%s]", me, sessionID)

	var res string
	err = s.DB.Get(&res, `
		UPDATE session SET active = FALSE WHERE token=$1 RETURNING id;
	`, sessionID)
	if err != nil {
		log.Printf("Close : remove session : err [%s]", err)
		return err
	}

	log.Printf("Close : res [%s]", res)

	return nil
}

// Designationer struct
type Designationer struct {
	DB *pgwp.Pool
}

// Designation type from database.
type Designation struct {
	ID              string `db:"id"`
	Identity        string `db:"identity"`
	Permission      []byte `db:"permission"`
	Resource        []byte `db:"resource"`
	IssuerID        string `db:"issuer_id"`
	IssuerSignature string `db:"issuer_signature"`
	ExpiresAt       string `db:"expires_at"`
}

// Search method searchs permission-designation relations for
// Identity.
//
// It doesn't validate permission signature because it would
// be CPU expensive. Every permission in database is view
// AS secure because Allow and Revoke methods do all the x509
// operations.
func (p *Designationer) Search(ctx qra.Identity, writer io.Writer, filter string) error {
	me := ctx.Me()

	// TODO; make filter rules

	x := strings.Split(filter, ":")
	if len(x) < 2 {
		return errResourceNotSpecified
	}
	permission := x[0]
	resource := x[1]

	var des Designation
	err := p.DB.Get(&des, `
		SELECT permission,resource,issuer_signature FROM designation
		WHERE identity=$1 AND permission=$2 AND resource=$3;
	`, me, permission, resource)
	if err != nil {
		log.Printf("Search : find designation: err [%s]", err)
	}

	// TODO; write to writer

	return err
}

// NPE struct stands for Non-Person Entity.
type NPE struct {
	ID         string `db:"id"`
	Name       string `db:"name"`
	Password   []byte `db:"password"`
	PrivateKey []byte `db:"private_key"`
	PublicKey  []byte `db:"public_key"`
}

// Allow method share permission from ctx to dst identity.
func (p *Designationer) Allow(ctx qra.Identity, password, permission, resource, dst string, expires time.Time) error {
	me := ctx.Me()
	log.Printf("Allow : identity [%v] permission [%s] resource [%s] dst_identity [%s]",
		me, permission, resource, dst)

	// validate who is trying to sign the permission.
	// ONLY system can make his own permissions.
	if me == dst && me != System {
		return ErrOwnSign
	}

	// locate identity and session.

	var token string
	err := ctx.Session(&token)
	if err != nil {
		return err
	}

	var sessionID string
	err = p.DB.Get(&sessionID, `
		SELECT token FROM session WHERE token=$1;
	`, token)
	if err != nil {
		log.Printf("Allow : locate session : err [%s]", err)
		return err
	}

	var npe NPE
	err = p.DB.Get(&npe, `
		SELECT
			id,
			name,
			password,
			private_key,
			public_key
		FROM identity
		WHERE name=$1;
	`, me)
	if err != nil {
		log.Printf("Allow : locate identity : err [%s]", err)
		return err
	}

	// verify password

	err = bcrypt.CompareHashAndPassword(npe.Password, []byte(password))
	if err != nil {
		return err
	}

	// decrypt private key

	privKey, err := AESCBCDecrypt([]byte(password), npe.PrivateKey)
	if err != nil {
		return err
	}

	// make signature

	// slug = identity:permission:resource:dst:time.RFC3339
	slug := fmt.Sprintf("%v:%v:%v:%v:%v", me, permission, resource, dst, expires.Format(time.RFC3339))
	data := []byte(slug)

	log.Printf("data [%s]", string(data))

	signature, err := generateSignature(privKey, data)
	if err != nil {
		return err
	}
	privKey = nil
	data = nil
	log.Printf("sign [%x]", signature)

	var res string
	err = p.DB.Get(&res, `
		INSERT INTO designation
		(issuer_id,issuer_signature,identity,permission,resource,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id;
	`, npe.ID, signature, dst, permission, resource, expires)
	if err != nil {
		log.Printf("Allow : store designation : err [%s]", err)
		return err
	}
	signature = nil

	log.Printf("designation id [%s]", res)

	return nil
}

// IdentityRevoke selects ID and Signature for comparison.
type IdentityRevoke struct {
	ID        string `db:"id"`
	Signature []byte `db:"issuer_signature"`
}

// Revoke method revokes a permission that ctx give to dst.
//
// Every revoke operation verifies signed x509 encryption.
func (p *Designationer) Revoke(ctx qra.Identity, password, permission, resource, dst string) error {
	me := ctx.Me()
	log.Printf("Revoke : username [%v]", me)

	// identity has session.

	var token string
	err := ctx.Session(&token)
	if err != nil {
		return err
	}

	var issuerID string
	err = p.DB.Get(&issuerID, `
		SELECT identity_id FROM session WHERE token=$1;
	`, token)
	if err != nil {
		log.Printf("Revoke : locate session : err [%s]", err)
		return ErrIdentityNotFound
	}

	// validate password

	var passhash []byte
	err = p.DB.Get(&passhash, `
		SELECT password FROM identity WHERE name=$1;
	`, me)
	if err != nil {
		log.Printf("Revoke : locate identity : err [%s]", err)
		return err
	}

	err = bcrypt.CompareHashAndPassword(passhash, []byte(password))
	if err != nil {
		log.Printf("Revoke : invalid credentials : err [%s]", err)
		return errInvalidCredentials
	}

	// TODO; verify sign

	var des IdentityRevoke
	err = p.DB.Get(&des, `
		SELECT id,issuer_signature FROM designation
		WHERE issuer_id=$1 AND identity=$2 AND
		permission=$3 AND resource=$4;
	`, issuerID, dst, permission, resource)
	if err != nil {
		log.Printf("Revoke : locate designation : err [%s] issuer id [%s] dst [%s] permission [%s] resource [%s]",
			err, issuerID, dst, permission, resource)
		return err
	}

	// delete from database.

	var res string
	err = p.DB.Get(&res, `
		DELETE FROM designation WHERE id=$1 RETURNING 'OK';
	`, des.ID)
	if err != nil {
		log.Printf("Revoke : delete designation : err [%s]", err)
		return err
	}

	return nil
}

// Context satisfies qra.Identity interface.
type Context struct {
	Username string
	Token    string
}

// Me method satisfies qra.Identity.
func (c Context) Me() string {
	return c.Username
}

// Session method satisfies qra.Identity.
func (c Context) Session(dst interface{}) error {
	p := reflect.ValueOf(dst)
	v := p.Elem()
	v.SetString(c.Token)
	return nil
}

// MakePassword generates a random password of l length.
func MakePassword(l int) string {
	rand.Seed(time.Now().UnixNano())
	bb := make([]byte, l)
	rand.Read(bb)
	b := make([]byte, ascii85.MaxEncodedLen(len(bb)))
	ascii85.Encode(b, bb)
	return string(b)[:l]
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
	h.Write(data)
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(cryptorand.Reader, privKey, crypto.SHA256, digest)
	if err != nil {
		return []byte{}, err
	}
	return s, nil
}
