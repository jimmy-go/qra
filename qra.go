// Package qra contains QuickRobutsAdmin interfaces for
// common tasks building administrator sites.
//
// QRA allows you a fast start for admins and API stability
// over the time.
/*
In order to understand qra interfaces you need to know
what these methods means:
RESOURCE
List: retrieve resource catalog.
Create: add a new resource item for catalog.
Delete: delete a resource item from catalog.
USER
UserList: user catalog selection.
UserHas: user has item from resource catalog?
UserAdd: add resource item to user.
UserRemove: remove resource item from user.
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
	DefaultManager = &QRA{}

	// ErrSessionerNil returned when QRA Session is nil.
	ErrSessionerNil = errors.New("qra: sessioner interface is nil")

	// ErrAccounterNil returned when QRA Account is nil.
	ErrAccounterNil = errors.New("qra: accounter interface is nil")

	// ErrRolerNil returned when QRA Role is nil.
	ErrRolerNil = errors.New("qra: roler interface is nil")

	// ErrPermissionerNil returned when QRA Permission is nil.
	ErrPermissionerNil = errors.New("qra: permissioner interface is nil")

	// ErrActionerNil returned when QRA Action is nil.
	ErrActionerNil = errors.New("qra: actioner interface is nil")
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

	// Locate method returns session or error.
	Locate(sessionID string) (interface{}, error)

	ImplementsSessioner()
}

// Accounter ACCOUNT managER interface
type Accounter interface {
	// Create method controls user account creation.
	Create(username string) error

	// Delete method controls user account remove.
	Delete(username string) error

	ImplementsAccounter()
}

// Roler ROLE managER interface
type Roler interface {
	// List method returns role catalog.
	List() ([]string, error)
	// Create method allow create roles on the way.
	Create(name string, data interface{}) error
	// Delete method removes role from role catalog making it
	// unavailable for everyone.
	Delete(ID string) error

	// UserRoles method return user roles.
	UserRoles(string) ([]string, error)
	// UserHas method validates user has role.
	UserHas(userID, roleID string) bool
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
	// UserHas method validates user has permission.
	UserHas(userID, permissionID string) bool
	// UserPermissionAdd method adds permission ID to user ID.
	UserPermissionAdd(userID, permissionID string) error
	// UserPermissionRemove method removes permission from
	// user.
	UserPermissionRemove(userID, permissionID string) error

	ImplementsPermissioner()
}

// Actioner ACTIONs managER interface.
type Actioner interface {
	// List method returns actions catalog.
	List() ([]string, error)
	// Create method creates a new action.
	Create(name string, data interface{}) error
	// Delete method deletes permission and make it unavailable
	// for everyone.
	Delete(name string) error

	// UserActions method returns user actions.
	UserActions(userID string) ([]string, error)
	// UserHas method validates user has action.
	UserHas(userID, actionID string) bool
	// UserActionAdd method adds action ID to user ID.
	UserActionAdd(userID, actionID string) error
	// UserActionRemove method removes permission from user.
	UserActionRemove(userID, actionID string) error

	ImplementsActioner()
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

// RegisterAccounter replaces Accounter of DefaultManager.
func RegisterAccounter(a Accounter) error {
	if a == nil {
		return ErrAccounterNil
	}
	DefaultManager.Account = a
	return nil
}

// MustRegisterAccounter calls RegisterAccounter function or
// panics.
func MustRegisterAccounter(a Accounter) {
	err := RegisterAccounter(a)
	if err != nil {
		panic(err)
	}
}

// RegisterRoler replaces Roler of DefaultManager.
func RegisterRoler(r Roler) error {
	if r == nil {
		return ErrRolerNil
	}
	DefaultManager.Role = r
	return nil
}

// MustRegisterRoler calls RegisterRoler function or
// panics.
func MustRegisterRoler(r Roler) {
	err := RegisterRoler(r)
	if err != nil {
		panic(err)
	}
}

// RegisterPermissioner replaces Permissioner of DefaultManager.
func RegisterPermissioner(p Permissioner) error {
	if p == nil {
		return ErrPermissionerNil
	}
	DefaultManager.Permission = p
	return nil
}

// MustRegisterPermissioner calls RegisterPermissioner function or
// panics.
func MustRegisterPermissioner(p Permissioner) {
	err := RegisterPermissioner(p)
	if err != nil {
		panic(err)
	}
}

// RegisterActioner replaces Actioner of DefaultManager.
func RegisterActioner(ac Actioner) error {
	if ac == nil {
		return ErrActionerNil
	}
	DefaultManager.Action = ac
	return nil
}

// MustRegisterActioner calls RegisterActioner function or
// panics.
func MustRegisterActioner(ac Actioner) {
	err := RegisterActioner(ac)
	if err != nil {
		panic(err)
	}
}

// Login wrapper for Sessioner.Login
func Login(username, password string) error {
	return DefaultManager.Session.Login(username, password)
}

// SessionCreate wrapper for Sessioner.Create
func SessionCreate(userID string) (string, error) {
	return DefaultManager.Session.Create(userID)
}

// SessionDelete wrapper for Sessioner.Delete
func SessionDelete(sessionID string) error {
	return DefaultManager.Session.Delete(sessionID)
}

// SessionLocate wrapper for Sessioner.Locate
func SessionLocate(sessionID string) (interface{}, error) {
	return DefaultManager.Session.Locate(sessionID)
}

// AccountCreate wrapper for Accounter.Create
func AccountCreate(username string) error {
	return DefaultManager.Account.Create(username)
}

// AccountDelete wrapper for Accounter.Delete
func AccountDelete(username string) error {
	return DefaultManager.Account.Delete(username)
}

// Delete wrapper for Accounter.Delete
func Delete(username string) error {
	return DefaultManager.Account.Delete(username)
}

// RolesList wrapper for Roler.List
func RolesList() ([]string, error) {
	return DefaultManager.Role.List()
}

// RolesCreate wrapper for Roler.Create
func RolesCreate(name string, data interface{}) error {
	return DefaultManager.Role.Create(name, data)
}

// RolesDelete wrapper for Roler.Delete
func RolesDelete(name string) error {
	return DefaultManager.Role.Delete(name)
}

// UserRoles wrapper for Roler.UserRoles
func UserRoles(userID string) ([]string, error) {
	return DefaultManager.Role.UserRoles(userID)
}

// HasRole wrapper for Roler.HasRole
func HasRole(userID, roleID string) bool {
	return DefaultManager.Role.UserHas(userID, roleID)
}

// UserRoleAdd wrapper for Roler.UserRoleAdd
func UserRoleAdd(userID, roleID string) error {
	return DefaultManager.Role.UserRoleAdd(userID, roleID)
}

// UserRoleRemove wrapper for Roler.UserRoleRemove
func UserRoleRemove(userID, roleID string) error {
	return DefaultManager.Role.UserRoleRemove(userID, roleID)
}

// PermissionsList wrapper for Permissioner.List
func PermissionsList() ([]string, error) {
	return DefaultManager.Permission.List()
}

// PermissionCreate wrapper for Permissioner.Create
func PermissionCreate(name string, data interface{}) error {
	return DefaultManager.Permission.Create(name, data)
}

// PermissionDelete wrapper for Permissioner.Delete
func PermissionDelete(name string) error {
	return DefaultManager.Permission.Delete(name)
}

// UserPermissions wrapper for Permissioner.UserPermissions
func UserPermissions(userID string) ([]string, error) {
	return DefaultManager.Permission.UserPermissions(userID)
}

// HasPermission wrapper for Permissioner.HasPermission
func HasPermission(userID, permissionID string) bool {
	return DefaultManager.Permission.UserHas(userID, permissionID)
}

// UserPermissionAdd wrapper for Permissioner.UserPermissionAdd
func UserPermissionAdd(userID, permissionID string) error {
	return DefaultManager.Permission.UserPermissionAdd(userID, permissionID)
}

// UserPermissionRemove wrapper for Permissioner.UserPermissionRemove
func UserPermissionRemove(userID, permissionID string) error {
	return DefaultManager.Permission.UserPermissionRemove(userID, permissionID)
}

// ActionsList wrapper for Actioner.List
func ActionsList() ([]string, error) {
	return DefaultManager.Action.List()
}

// ActionCreate wrapper for Actioner.Create
func ActionCreate(name string, data interface{}) error {
	return DefaultManager.Action.Create(name, data)
}

// ActionDelete wrapper for Actioner.Delete
func ActionDelete(name string) error {
	return DefaultManager.Action.Delete(name)
}

// UserActions wrapper for Actioner.UserActions
func UserActions(userID string) ([]string, error) {
	return DefaultManager.Action.UserActions(userID)
}

// HasAction wrapper for Actioner.HasAction
func HasAction(userID, actionID string) bool {
	return DefaultManager.Action.UserHas(userID, actionID)
}

// UserActionAdd wrapper for Actioner.UserActionAdd
func UserActionAdd(userID, actionID string) error {
	return DefaultManager.Action.UserActionAdd(userID, actionID)
}

// UserActionRemove wrapper for Actioner.UserActionRemove
func UserActionRemove(userID, actionID string) error {
	return DefaultManager.Action.UserActionRemove(userID, actionID)
}
