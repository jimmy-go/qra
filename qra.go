// Package qra contains QuickRobutsAdmin interfaces for
// common tasks building administrator sites.
//
// QRA allows you a fast start for admins and API stability
// over the time.
/*
	In order to understand qra interfaces you need to know
	what these means:
				RESOURCE
		List: retrieve catalog.
		Create: insert a new item for catalog.
		Delete: delete item from catalog.
				USER
		UserList: user catalog.
		UserHas: user has item from catalog?
		UserAdd: add item to user.
		UserRemove: remove item from user.
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
package qra

import "errors"

var (
	// DefaultManager is the default QRA Manager.
	DefaultManager *QRA

	// ErrSessionerNil returned when replace Sessioner is nil.
	ErrSessionerNil = errors.New("qra: sessioner is nil")
)

// QRA struct is the container for common administrator
// operations split between interfaces.
//
// Session control: Sessioner-interface.
// Account management: Accounter-interface.
// Role management: Roler-interface.
// Rermissions: Permissioner-interface.
type QRA struct {
	Account    Accounter
	Session    Sessioner
	Role       Roler
	Permission Permissioner
	Action     Actioner
}

// New returns a new QRA struct.
func New(a Accounter, s Sessioner, r Roler, p Permissioner, ac Actioner) (*QRA, error) {
	q := &QRA{
		Account:    a,
		Session:    s,
		Role:       r,
		Permission: p,
		Action:     ac,
	}
	return q, nil
}

// Sessioner SESSIONs doEr interface
type Sessioner interface {
	// Login method validates username and password.
	Login(username, password string) error

	// Create method generates a new session for user
	// returning sessionID.
	Create(userID string) (sessionID string, err error)

	// Delete method deletes session ID.
	Delete(sessionID string) error

	ImplementsSessioner()
}

// Accounter ACCOUNT managER interface
type Accounter interface {
	// Create method controls user account creation.
	Create(username string) error

	// Delete method controls user account remove.
	Delete(token string) error

	ImplementsAccounter()
}

// Roler ROLE managER interface
type Roler interface {
	// List method returns role catalog.
	List() ([]string, error)
	// Create method allow create roles on the way.
	Create(name string, data interface{}) error
	// Delete method removes role from role catalog making it
	// unavailable for every other user.
	Delete(ID string) error

	// UserRoles method return user roles.
	UserRoles(string) ([]string, error)
	// HasRole method validates user has role.
	HasRole(userID, roleID string) bool
	// UserRoleAdd method adds role ID to user ID.
	UserRoleAdd(userID, roleID string) error
	// UserRoleRemove method removes role from user.
	UserRoleRemove(userID, roleID string) error

	ImplementsRoler()
}

// Permissioner PERMISSION managER interface.
type Permissioner interface {
	// List method returns permissions catalog.
	List() ([]string, error)
	// Create method creates a new permission.
	Create(name string, data interface{}) error
	// Delete method deletes permission and make
	// it unavailable for everyone.
	Delete(permissionID string) error

	// UserPermissions method returns user permissions.
	UserPermissions(userID string) ([]string, error)
	// UserPermissionAdd method adds permission ID to user ID.
	UserPermissionAdd(userID, permissionID string) error
	// UserPermissionRemove method removes permission from
	// user.
	UserPermissionRemove(userID, permissionID string) error

	ImplementsPermissioner()
}

// Actioner ACTIONs managER interface.
type Actioner interface {
	List() ([]string, error)
	Create(name, data interface{}) error
	Delete(name) error

	UserActions(userID string) ([]string, error)
	UserActionAdd(userID string) ([]string, error)
	UserActionRemove(userID string) ([]string, error)
}

// RegisterSessioner replaces Sessioner of DefaultManager.
func RegisterSessioner(s Sessioner) error {
	if s == nil {
		return ErrSessionerNil
	}

	DefaultManager.Session = s
	return nil
}

// MustRegisterSessioner calls RegisterSessioner function or
// panics.
func MustRegisterSessioner(s Sessioner) {
	err := RegisterSessioner(s)
	if err != nil {
		panic(err)
	}
}

// Login wrapper for Sessioner.Login
func Login(username, password string) error {
	return DefaultManager.Session.Login(username, password)
}

// SessionCreate wrapper for Sessioner.SessionCreate
func SessionCreate(userID string) (string, error) {
	return DefaultManager.Session.SessionCreate(userID)
}

// SessionDelete wrapper for Sessioner.SessionDelete
func SessionDelete(sessionID string) error {
	return DefaultManager.Session.SessionDelete(sessionID)
}

// Create calls the Accounter interface in DefaultManager.
func Create(username string) error {
	return DefaultManager.Account.Create(username)
}

// Delete wrapper for Accounter.Delete
func Delete(username string) error {
	return DefaultManager.Account.Create(username)
}

// RolesList wrapper for Roler.RolesList
func RolesList() ([]string, error) {
	return DefaultManager.Role.RolesList()
}

// RoleCreate wrapper for Roler.RoleCreate
func RoleCreate(name string, data interface{}) error {
	return DefaultManager.Role.RoleCreate(name, data)
}

// RoleDelete wrapper for Roler.RoleDelete
func RoleDelete(ID string) error {
	return DefaultManager.Role.RoleDelete(ID)
}

// UserRoles calls the Roler interface in DefaultManager.
func UserRoles(ID string) ([]string, error) {
	return DefaultManager.Role.UserRoles(ID)
}

// PermissionsList calls the Permissioner interface in DefaultManager.
func PermissionsList() ([]string, error) {
	return DefaultManager.Permission.PermissionsList()
}

// UserPermissions calls the Permissioner interface in DefaultManager.
func UserPermissions(ID string) ([]string, error) {
	return DefaultManager.Permission.UserPermissions(ID)
}
