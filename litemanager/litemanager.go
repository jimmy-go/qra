// Package litemanager contains the Default manager for roles,
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
package litemanager

import (
	// import driver in main
	// _ "github.com/mattn/go-sqlite3"

	"github.com/jimmy-go/pgwp"
	"github.com/jimmy-go/qra"
)

var (
	sessions    *Session
	accounts    *Account
	roles       *Role
	permissions *Permission

	// Db database for this manager.
	Db *pgwp.Pool
)

// Connect starts the manager.
func Connect(driver, connectURL string) error {
	var err error
	Db, err = pgwp.Connect(driver, connectURL, 5, 5)
	if err != nil {
		return err
	}

	// register qra default manager or panics.
	qra.MustRegisterSessioner(sessions)
	qra.MustRegisterAccounter(accounts)
	qra.MustRegisterRoler(roles)
	qra.MustRegisterPermissioner(permissions)
	return nil
}

// Login login.
func (dm *Manager) Login(username, password string) error {
	var users []string
	err := dm.Db.Select(&users, `
		SELECT
			id
		FROM person
		LIMIT 100;
	`)
	return users, err
}

// Users func
func (dm *Manager) Users() ([]string, error) {
	var users []string
	err := dm.Db.Select(&users, `
		SELECT
			id
		FROM person
		LIMIT 100;
	`)
	return users, err
}

// Roles func
func (dm *Manager) Roles() []string {
	var roles []string
	err := dm.Db.Select(&roles, `
		SELECT
			id
		FROM role
		LIMIT 100;
	`)
	return roles, err
}

// RolesByUser func
func (dm *Manager) RolesByUser(ID string) []string {
	var roles []string
	err := dm.Db.Select(&roles, `
		SELECT
			id
		FROM role
		WHERE user_id=$1
		LIMIT 100;
	`, ID)
	return roles, err
}

// Permissions func
func (dm *Manager) Permissions() []string {
	var pers []string
	err := dm.Db.Select(&pers, `
		SELECT
			id
		FROM permission
		LIMIT 100;
	`)
	return pers, err

}

// PermissionsByUser func
func (dm *Manager) PermissionsByUser(ID string) []string {
	var pers []string
	err := dm.Db.Select(&pers, `
		SELECT
			id
		FROM permission
		WHERE user_id=$1
		LIMIT 100;
	`, ID)
	return pers, err

}
