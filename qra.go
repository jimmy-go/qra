// Package qra contains QuickRobutsAdmin interfaces for
// RBAC, MAC, DAC, ABAC and ZBAC systems.
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

import (
	"errors"
<<<<<<< HEAD
	"log"
=======
	"io"
	"time"
>>>>>>> release/v0.0.2
)

var (
	// DefaultManager is the default QRA Manager.
	DefaultManager = &QRA{}

	// ErrAuthenticationNil returned when QRA authentication
	// interface is nil.
	ErrAuthenticationNil = errors.New("qra: authentication interface is nil")

	// ErrDesignationNil returned when QRA authorization-designation
	// interface is nil.
	ErrDesignationNil = errors.New("qra: authorization-designation interface is nil")
)

// QRA struct is the container for common administrator
// operations split between interfaces.
type QRA struct {
	Authentication           Authentication
	DesignationAuthorization Designation
}

// New returns a new QRA struct.
func New(a Authentication, d Designation) (*QRA, error) {
	q := &QRA{
		Authentication:           a,
		DesignationAuthorization: d,
	}
	return q, nil
}

// Identity interface for management of identities (users).
type Identity interface {
	// Me method returns identity name (username, userID, etc.)
	Me() string

	// Session method returns current session or error.
	// If session is found then is written to dst.
	Session(dst interface{}) error
}

// Authentication interface for session management of users.
type Authentication interface {
	// Authenticate method makes login to user. It will call
	// Me method to retrieve Identity username, validate
	// if not session is present with Session method.
	// Developer implementations of Authentication interface
	// MUST have session storage methods.
	Authenticate(ctx Identity, password string, dst interface{}) error

	// Close method will delete session of current identity.
	Close(ctx Identity) error
}

// Designation interface stands for Authorization-Designation
// operations.
type Designation interface {
	// Search permission-designations and writes to writer.
	// Recommended format for results is: `permission:resource`.
	// Return error if not permission for identity was found.
	// Filter parameter will allow search permissions by
	// name, resource and has pagination (e.g.: `permission:resource/1-36` or
	// `permission:resource/since/123abc`).
	Search(ctx Identity, writer io.Writer, filter string) error

	// Allow method shares identity permission over resource with dst.
	Allow(ctx Identity, password, permission, resource, dst string, expiresAt time.Time) error

	// Revoke method will revoke a permission that ctx previously
	// give to dst.
	Revoke(ctx Identity, password, permission, resource, dst string) error
}

// RegisterAuthentication replaces Authentication of DefaultManager.
func RegisterAuthentication(a Authentication) error {
	if a == nil {
		return ErrAuthenticationNil
	}
	DefaultManager.Authentication = a
	return nil
}

// MustRegisterAuthentication calls RegisterAuthentication function or
// panics.
func MustRegisterAuthentication(a Authentication) {
	err := RegisterAuthentication(a)
	if err != nil {
		panic(err)
	}
}

// RegisterDesignation replaces Authentication of DefaultManager.
func RegisterDesignation(d Designation) error {
	if d == nil {
		return ErrDesignationNil
	}
	DefaultManager.DesignationAuthorization = d
	return nil
}

// MustRegisterDesignation calls RegisterDesignation function or
// panics.
func MustRegisterDesignation(d Designation) {
	err := RegisterDesignation(d)
	if err != nil {
		panic(err)
	}
}

<<<<<<< HEAD
// Login wrapper for Sessioner.Login
func Login(username, password string) error {
	log.Printf("QRA : Login : user [%s] pass [%s]", username, password)
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
=======
// Authenticate wrapper for DefaultManager.Authentication.Authenticate.
func Authenticate(ctx Identity, password string, dst interface{}) error {
	return DefaultManager.Authentication.Authenticate(ctx, password, dst)
>>>>>>> release/v0.0.2
}

// Close wrapper for DefaultManager.Authentication.Close.
func Close(ctx Identity) error {
	return DefaultManager.Authentication.Close(ctx)
}

// Search wrapper for DefaultManager.Designation.Search.
func Search(ctx Identity, writer io.Writer, filter string) error {
	return DefaultManager.DesignationAuthorization.Search(ctx, writer, filter)
}

// Allow wrapper for DefaultManager.Designation.Allow.
func Allow(ctx Identity, password, permission, resource, dst string, expiresAt time.Time) error {
	return DefaultManager.DesignationAuthorization.Allow(ctx, password, permission, resource, dst, expiresAt)
}

// Revoke wrapper for DefaultManager.Designation.Revoke.
func Revoke(ctx Identity, password, permission, resource, dst string) error {
	return DefaultManager.DesignationAuthorization.Revoke(ctx, password, permission, resource, dst)
}
