// Package pgmanager contains a QRA manager for PostgreSQL.
/*
	This implementation has no flavor for permission structure. In the meanwhile
	will be named "QRA PG A" flavor.
*/
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
	// don't forget import driver in main
	// _ "github.com/lib/pq"

	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jimmy-go/qra"
	"github.com/jmoiron/sqlx"
	"github.com/satori/go.uuid"
)

// Connect starts the manager.
func Connect(driver, connectURL string) error {
	if err := connectAndRegister(driver, connectURL); err != nil {
		return err
	}
	return nil
}

var (
	authentication *Authenticationer
	designation    *Designationer

	// Db database for this manager.
	Db *sqlx.DB
)

const (
	// PERMISSION CATALOG. This permissions are the same on migration sql file.

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
)

const (
	// PassMin defines the minimum length of a password.
	PassMin = 8

	// System defines identity username for SYSTEM.
	System = "system"

	// SessionDuration defines the duration for a session on database.
	// default 3 months.
	SessionDuration = time.Duration(24 * time.Hour * 30 * 3)

	// PermissionDuration defines the duration default for a permission.
	// default 1 year.
	PermissionDuration = time.Duration(24 * time.Hour * 365 * 1)

	// StatusActive permission status active.
	StatusActive = "active"
	// StatusInactive permission status inactive.
	StatusInactive = "inactive"
)

func connectAndRegister(driver, connectURL string) error {
	var err error
	Db, err = sqlx.Open(driver, connectURL)
	if err != nil {
		return err
	}
	authentication = &Authenticationer{}
	designation = &Designationer{}

	qra.MustRegisterAuthentication(authentication)
	qra.MustRegisterDesignation(designation)
	if err := systemCheck(); err != nil {
		return err
	}
	return nil
}

// systemCheck will verifies several things:
//		Identity system exists.
//		System permission designation.
func systemCheck() error {
	var systemID string
	err := Db.Get(&systemID, `
		SELECT id FROM identity WHERE name=$1;
	`, System)
	if err != nil {
		log.Printf("SYSTEM IDENTITY NOT FOUND: creating system")

		// generate random password for "system".
		randpass, err := MakePassword(64)
		if err != nil {
			return err
		}

		if _, err := makeUser(System, randpass); err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return qra.ErrSystemNotFound
		}

		ctx := &Context{
			Username: System,
		}

		// generate session

		err = authentication.Authenticate(ctx, randpass, &ctx.Token)
		if err != nil {
			log.Printf("can't  create system identity : authenticate : err [%s]", err)
			return qra.ErrSystemNotFound
		}

		// allow terminal session for identity "system"

		expiresAt := time.Now().UTC().Add(PermissionDuration)
		err = designation.Allow(ctx, randpass, PermSessionOn, "terminal", System, expiresAt)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return qra.ErrSystemNotFound
		}

		// allow create identity for user "system"

		err = designation.Allow(ctx, randpass, PermIdentityCreate, "*", System, expiresAt)
		if err != nil {
			log.Printf("can't  create system identity : err [%s]", err)
			return qra.ErrSystemNotFound
		}

		// show once system password

		log.Printf("SYSTEM IDENTITY PASSWORD: %s", randpass)
	}

	return nil
}

// Authenticationer struct
type Authenticationer struct{}

// Authenticate makes login for Identity.
func (s *Authenticationer) Authenticate(ctx qra.Identity, password string, dst interface{}) error {
	me := ctx.Me()
	log.Printf("Authenticate : username [%s] password [%s]", me, password)

	var u IdentitySimple
	err := Db.Get(&u, `
		SELECT id,password FROM identity WHERE name=$1;
	`, me)
	if err != nil {
		return err
	}
	// don't waste hashing time
	if len(u.Password) < 1 {
		return qra.ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword(u.Password, []byte(password))
	if err != nil {
		return qra.ErrInvalidCredentials
	}

	expiresAt := time.Now().UTC().Add(SessionDuration)
	token := uuid.NewV4().String() + "." + uuid.NewV4().String()

	err = Db.Get(dst, `
		INSERT INTO session (identity_id,token,expires_at,status)
		VALUES ($1,$2,$3,$4)
		RETURNING token;
	`, u.ID, token, expiresAt, StatusActive)
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
	err = Db.Get(&res, `
		UPDATE session SET status=$2 WHERE token=$1 RETURNING id;
	`, sessionID, StatusInactive)
	if err != nil {
		log.Printf("Close : remove session : err [%s]", err)
		return err
	}

	log.Printf("Close : res [%s]", res)

	return nil
}

// IdentitySimple for identity retrieve.
type IdentitySimple struct {
	ID       string `db:"id"`
	Password []byte `db:"password"`
}

// Designationer struct
type Designationer struct{}

// Search method searchs permission-designation relations for
// Identity.
//
// It doesn't validate permission signature because it would
// be CPU expensive. Every permission in database is view
// AS secure because Allow and Revoke methods do all the x509
// operations.
//
// if dst is nil then Search will act as "HasPermission" method.
//
// format 1: permission:resource
// format 2: "designation.id" + "." + "designation.signature"
func (p *Designationer) Search(ctx qra.Identity, v interface{}, filter string) error {
	me := ctx.Me()

	meID, err := meID(me)
	if err != nil {
		return err
	}

	fr, err := parseFilter(filter)
	if err != nil {
		return err
	}

	log.Printf("Search : me [%s] me id [%s] filter [%#v]", me, meID, fr)

	if v == nil {
		var c int
		err := Db.Get(&c, `
			SELECT count(id)
			FROM designation
			WHERE identity_id=$1 AND permission=$2 AND resource=$3;
		`, meID, fr.Permission, fr.Resource)
		log.Printf("Search : find designation : c [%d]", c)
		if err != nil {
			log.Printf("Search : find designation : err [%s]", err)
			return err
		}
		if c < 1 {
			return errors.New("not found")
		}
		return nil
	}

	err = Db.Get(v, `
		SELECT
			permission,resource,issuer_signature
		FROM designation
		WHERE identity_id=$1 AND permission=$2 AND resource=$3;
	`, meID, fr.Permission, fr.Resource)
	if err != nil {
		log.Printf("Search : find designation : err [%s]", err)
		return err
	}

	return nil
}

// Filter struct.
type Filter struct {
	Permission string
	Resource   string
}

func parseFilter(s string) (*Filter, error) {
	x := strings.Split(s, ":")
	if len(x) != 2 {
		return nil, qra.ErrResourceNotSpecified
	}

	fr := &Filter{
		Permission: x[0],
		Resource:   x[1],
	}
	return fr, nil
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
		return qra.ErrOwnSign
	}

	// locate identity and session.

	var token string
	err := ctx.Session(&token)
	if err != nil {
		return err
	}

	var sessionID string
	err = Db.Get(&sessionID, `
		SELECT token FROM session WHERE token=$1;
	`, token)
	if err != nil {
		log.Printf("Allow : locate session : err [%s]", err)
		return err
	}

	var dstID string
	err = Db.Get(&dstID, `
		SELECT id FROM identity WHERE name=$1;
	`, dst)
	if err != nil {
		log.Printf("Allow : locate dst id : err [%s]", err)
		return err
	}

	var npe NPE
	err = Db.Get(&npe, `
		SELECT
			id,name,password,private_key,public_key
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

	// log.Printf("data [%s]", string(data))

	signature, err := generateSignature(privKey, data)
	if err != nil {
		return err
	}
	privKey = nil
	data = nil
	// log.Printf("sign [%x]", signature)

	var res string
	err = Db.Get(&res, `
		INSERT INTO designation
		(issuer_id,issuer_signature,identity_id,permission,resource,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id;
	`, npe.ID, signature, dstID, permission, resource, expires)
	if err != nil {
		log.Printf("Allow : store designation : err [%s]", err)
		return err
	}
	signature = nil

	// log.Printf("designation id [%s]", res)

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
	err = Db.Get(&issuerID, `
		SELECT identity_id FROM session WHERE token=$1;
	`, token)
	if err != nil {
		log.Printf("Revoke : locate session : err [%s]", err)
		return qra.ErrIdentityNotFound
	}

	// validate password

	var passhash []byte
	err = Db.Get(&passhash, `
		SELECT password FROM identity WHERE name=$1;
	`, me)
	if err != nil {
		log.Printf("Revoke : locate identity : err [%s]", err)
		return err
	}

	err = bcrypt.CompareHashAndPassword(passhash, []byte(password))
	if err != nil {
		log.Printf("Revoke : invalid credentials : err [%s]", err)
		return qra.ErrInvalidCredentials
	}

	dstID, err := meID(dst)
	if err != nil {
		return err
	}

	// TODO; verify sign

	var des IdentityRevoke
	err = Db.Get(&des, `
		SELECT id,issuer_signature FROM designation
		WHERE issuer_id=$1 AND identity_id=$2 AND
		permission=$3 AND resource=$4;
	`, issuerID, dstID, permission, resource)
	if err != nil {
		log.Printf("Revoke : locate designation : err [%s] issuer id [%s] dst [%s] permission [%s] resource [%s]",
			err, issuerID, dstID, permission, resource)
		return err
	}

	// delete from database.

	var res string
	err = Db.Get(&res, `
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
