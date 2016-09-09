// Package rawmanager contains a QRA manager only on cache.
// Was done for most simple example of QRA manager.
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
package rawmanager

// Permission struct
type Permission struct {
	Data map[string][]string
}

// List func.
func (p *Permission) List() ([]string, error) {
	return []string{}, nil
}

// Create func.
func (p *Permission) Create(name string, data interface{}) error {
	return nil
}

// Delete func.
func (p *Permission) Delete(ID string) error {
	return nil
}

// UserPermissions func.
func (p *Permission) UserPermissions(userID string) ([]string, error) {
	return []string{}, nil
}

// UserHas func.
func (p *Permission) UserHas(userID, permissionID string) bool {
	return true
}

// UserPermissionAdd func.
func (p *Permission) UserPermissionAdd(userID, permissionID string) error {
	return nil
}

// UserPermissionRemove func.
func (p *Permission) UserPermissionRemove(userID, permissionID string) error {
	return nil
}

// ImplementsPermissioner satisfies Permissioner.
func (p *Permission) ImplementsPermissioner() {}
