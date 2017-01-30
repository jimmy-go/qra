// Package qmenu contains QuickRobutsAdmin interfaces for RBAC, MAC, DAC, ABAC
// and ZBAC systems.
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
package qmenu

import (
	"errors"

	"github.com/jimmy-go/qra"
)

// Set sets the menus. Must be called at init time.
func Set(ms []*Menu) error {
	for i := range ms {
		if ms[i] == nil {
			return errors.New("nil menu")
		}

		m := ms[i]
		if len(m.Role) < 1 {
			return errors.New("empty menu key")
		}
		menus[m.Role] = m
	}
	return nil
}

// Menu struct represents UI menu.
type Menu struct {
	Name  string
	Role  string
	Icon  string
	Link  string
	Badge int
}

var (
	// menus and roles required.
	menus = make(map[string]*Menu)
)

// UserMenus returns user available menus.
func UserMenus(userID string) []*Menu {
	// FIXME; qra search method will return a range of keys to prevent too many
	// queries.
	var list []*Menu
	for i := range menus {
		m := menus[i]

		err := qra.Search(Ctx{userID}, nil, "read:"+m.Role)
		if err != nil {
			continue
		}
		list = append(list, m)
	}
	return list
}

// Ctx satisfies Identity interface.
type Ctx struct {
	UserID string
}

// Me method.
func (c Ctx) Me() string {
	return c.UserID
}

// Session method.
func (c Ctx) Session(dst interface{}) error {
	// DO nothing
	return nil
}
