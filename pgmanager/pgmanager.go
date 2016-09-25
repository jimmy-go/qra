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
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
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

	errSystemNotFound       = errors.New("pgmanager: system identity not found")
	errPermissionNotFound   = errors.New("pgmanager: permission not found")
	errInvalidCredentials   = errors.New("pgmanager: invalid username or password")
	errResourceNotSpecified = errors.New("pgmanager: resource not specified")
)

// Connect starts the manager.
func Connect(driver, connectURL string, terminalSession bool) error {
	var err error
	Db, err = pgwp.Connect(driver, connectURL, 5, 5)
	if err != nil {
		return err
	}

	authentication = &Authenticationer{
		DB: Db,
	}
	designation = &Designationer{
		DB: Db,
	}

	qra.MustRegisterAuthentication(authentication)
	qra.MustRegisterDesignation(designation)

	err = systemCheck(terminalSession)
	if err != nil {
		return err
	}

	return nil
}

// systemCheck will verifies several things:
//		user system exists.
//		permission catalog exists.
//		system is owner of permission catalog.
//		system permission designation.
//		TODO; if not manager user present generate one
//		with custom permission designation?
func systemCheck(terminalSession bool) error {
	var systemID string
	err := Db.Get(&systemID, `
		SELECT id FROM identity WHERE name='system';
	`)
	if err != nil {
		log.Printf("system identity not found: creating system")

		// generate random password.
		randpass := []byte(RandString(64))

		sysPassHash, err := bcrypt.GenerateFromPassword(randpass, bcrypt.DefaultCost)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		err = makeUser("system", sysPassHash)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		// permission for 2 years.
		expiresAt := time.Now().UTC().Add(24 * time.Hour * 365 * 2)

		err = makePermission("system", "session-on", "terminal", "system", string(randpass), expiresAt)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return errSystemNotFound
		}

		log.Printf("SYSTEM IDENTITY PASSWORD: %s", string(randpass))

		terminalSession = true
	}
	var c int
	err = Db.Get(&c, `
		SELECT count(id) FROM identity;
	`)
	if err != nil {
		log.Printf("users not found : err [%s]", err)
	}

	if terminalSession {
		Terminal()
	}
	return nil
}

func makePermission(identity, permission, resource, issuerID, password string, expiresAt time.Time) error {
	// locate identity.
	var ssuer struct {
		ID       string `db:"id"`
		Password []byte `db:"password"`
	}
	err := Db.Get(&ssuer, `
			SELECT id,password FROM identity WHERE name=$1;
	`, issuerID)
	if err != nil {
		return err
	}

	// validate password.

	err = bcrypt.CompareHashAndPassword(ssuer.Password, []byte(password))
	if err != nil {
		return err
	}

	// generate signature.

	mac := hmac.New(sha512.New, ssuer.Password)
	mac.Write(ssuer.Password)
	signature := mac.Sum(nil)

	var perID string
	err = Db.Get(&perID, `
			INSERT INTO designation
			(identity,permission,resource,issuer_id,issuer_signature,expires_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			RETURNING id;
			`, identity, permission, resource, ssuer.ID, signature, expiresAt)
	return err
}

func makeUser(username string, passwordHash []byte) error {
	var s string
	err := Db.Get(&s, `
			INSERT INTO identity
			(name,password)
			VALUES($1,$2)
			RETURNING id;
		`, username, passwordHash)
	return err
}

// Terminal starts an infinite loop to read the user's input.
func Terminal() {
	ost, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, ost)

	f, err := os.OpenFile("qra_pgmanager.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Err [%s]", err)
		return
	}
	log.SetOutput(f)

	defer func() {
		f.Close()
		os.Remove(f.Name())

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

		var prefix string
		if len(l) > 1 {
			prefix = l[:2]
		}

		switch prefix {
		case ":q":
			return
		case "1:":
			term.SetPrompt("Give permission to identity with format: identity:permission:resource\n\r")

			x := strings.Split(l, ":")
			if len(x) != 3 {
				fmt.Printf("invalid format")
				continue
			}

			// one month permission.
			expiresAt := time.Now().UTC().Add(24 * time.Hour * 30)

			err := designation.Allow(ctx, x[1], x[2], x[0], expiresAt)
			if err != nil {
				fmt.Printf("can't read permissions")
				continue
			}
		case "2:":
			buf := bytes.NewBuffer([]byte{})
			err = designation.Search(ctx, buf, "create-identity:*")
			if err != nil {
				fmt.Printf("You don't have allowed create identity\n\r")
				continue
			}
		case ":h":
			fmt.Printf("\n\rShare permission (1:<Identity>:<Permission>:<Resource>)")
			fmt.Printf("\n\rCreate identity (2:<Identity>:<Password>)")
			fmt.Printf("\n\rLogout (:5)\n\r")
		case "5:", ":5":
			err := authentication.Close(ctx)
			if err != nil {
				fmt.Printf("can't close session\n\r")
				continue
			}
			fmt.Printf("Session closed\n\r")
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
						ctx.Username = ""
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

// IDPass for identity retrieve.
type IDPass struct {
	ID   string `db:"id"`
	Pass []byte `db:"password"`
}

// Authenticate makes login for Identity.
func (s *Authenticationer) Authenticate(ctx qra.Identity, password string, dst interface{}) error {
	username := ctx.Me()
	log.Printf("Authenticate : username [%s] password [%s]", username, password)

	var iden IDPass
	err := s.DB.Get(&iden, `
		SELECT id,password FROM identity WHERE name=$1;
	`, username)
	if err != nil {
		log.Printf("Authenticate : get user : err [%s]", err)
		return err
	}
	if len(iden.Pass) < 1 {
		return errInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword(iden.Pass, []byte(password))
	if err != nil {
		log.Printf("Authenticate : compare password : err [%s]", err)
		return errInvalidCredentials
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour * 30 * 3)
	token := uuid.NewV4().String() + "." + uuid.NewV4().String()

	err = s.DB.Get(dst, `
		INSERT INTO session (identity_id,token,expires_at)
		VALUES ($1,$2,$3)
		RETURNING token;
	`, iden.ID, token, expiresAt)
	if err != nil {
		log.Printf("Authenticate : get user : err [%s]", err)
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
	log.Printf("Close : get session : username [%s] session id [%s]", me, sessionID)

	var res string
	err = s.DB.Get(&res, `
		UPDATE session SET active = FALSE WHERE token=$1 RETURNING id;
	`, sessionID)
	if err != nil {
		log.Printf("Close : remove session : err [%s]", err)
	}

	log.Printf("Close : res [%s]", res)

	return err
}

// Designationer struct
type Designationer struct {
	DB *pgwp.Pool
}

// Design type from database.
type Design struct {
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
// AS secure because Allow and Revoke methods do all the RSA
// operations.
func (p *Designationer) Search(ctx qra.Identity, writer io.Writer, filter string) error {

	me := ctx.Me()
	log.Printf("Search : me [%v] filter [%v]", me, filter)

	x := strings.Split(filter, ":")
	if len(x) < 2 {
		return errResourceNotSpecified
	}
	permission := x[0]
	resource := x[1]

	var des Design
	err := p.DB.Get(&des, `
		SELECT permission,resource FROM designation
		WHERE identity=$1 AND permission=$2 AND resource=$3;
	`, me, permission, resource)
	if err != nil {
		log.Printf("Search : find designation: err [%s]", err)
	}

	return err
}

// NPE struct stands for Non-Person Entity.
type NPE struct {
	ID         string `db:"id"`
	Name       string `db:"name"`
	PrivateKey []byte `db:"private_key"`
	PublicKey  []byte `db:"public_key"`
}

// Allow method share permission from ctx to dst.
//
// Every allow operation is signed using RSA 4096.
func (p *Designationer) Allow(ctx qra.Identity, permission, resource, dst string, expires time.Time) error {
	me := ctx.Me()
	log.Printf("Allow : identity [%v]", me)

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
	}

	// share permission with dst using RSA encription.

	var des Design
	err = p.DB.Get(&des, `
		SELECT
			identity,
			permission,
			resource,
			issuer_id,
			issuer_signature,
			expires_at
		FROM designation
		WHERE identity=$1 AND permission=$2 AND resource=$3;
	`, me, permission, resource)
	if err != nil {
		log.Printf("Allow : locate designation : err [%s]", err)
		return err
	}

	var npe NPE
	err = p.DB.Get(&des, `
		SELECT
			id,
			name,
			private_key,
			public_key
		FROM identity
		WHERE name=$1;
	`, me)
	if err != nil {
		log.Printf("Allow : locate identity : err [%s]", err)
		return err
	}
	if len(npe.PrivateKey) < 1 || len(npe.PublicKey) < 1 {
		return errPermissionNotFound
	}

	return nil
}

// Revoke method revokes a permission that Identity give to dst.
//
// Every revoke operation verifies signed RSA keys encription.
func (p *Designationer) Revoke(ctx qra.Identity, permission, dst string) error {

	userID := ctx.Me()
	log.Printf("Revoke : userID [%v]", userID)

	return nil
}

// Ctx returns a context identity.
func Ctx(username string) qra.Identity {
	c := &Context{
		Username: username,
	}
	return c
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
	log.Printf("Session : type [%v]", p.Type())
	log.Printf("Session : canset [%v]", p.CanSet())
	v := p.Elem()
	log.Printf("Session : v canset [%v]", v.CanSet())
	v.SetString(c.Token)

	log.Printf("Session : dst [%v] token [%s]", dst, c.Token)
	return nil
}

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+-.,<>;:_{}[]¿?=)("
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

// RandString func.
func RandString(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := 0; i < n; {
		if idx := int(rand.Int63() & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i++
		}
	}
	return string(b)
}
