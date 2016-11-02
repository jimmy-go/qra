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

import (
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/jimmy-go/qra"
)

var (
	errUserNotFound       = errors.New("authorization: user not found")
	errPermissionNotFound = errors.New("authorization: permission not found")
)

// Designationer struct
type Designationer struct {
	Data  map[string][]string
	Share map[string]string

	sync.RWMutex
}

// Search method searchs permission-designation relations for
// Identity.
func (p *Designationer) Search(ctx qra.Identity, writer io.Writer, filter string) error {
	p.RLock()
	defer p.RUnlock()

	userID := ctx.Me()
	log.Printf("Search : userID [%v] filter [%v]", userID, filter)

	permissions, ok := p.Data[userID]
	if !ok {
		return errUserNotFound
	}

	// TODO; make filter funtionality

	for i := range permissions {
		per := permissions[i]

		if per == filter {
			_, err := writer.Write([]byte(per))
			if err != nil {
				return err
			}
			return nil
		}
	}

	return errPermissionNotFound
}

// Allow method share permission from ctx to dst.
func (p *Designationer) Allow(ctx qra.Identity, permission, resource, dst string, expires time.Time) error {
	p.RLock()
	defer p.RUnlock()

	userID := ctx.Me()
	log.Printf("Allow : userID [%v]", userID)

	permissions, ok := p.Data[userID]
	if !ok {
		return errUserNotFound
	}

	// TODO; valite expiration time

	for i := range permissions {
		if permission == permissions[i] {
			p.Share[dst] = permission
			return nil
		}
	}

	return errPermissionNotFound
}

// Revoke method revokes a permission that Identity give to dst.
func (p *Designationer) Revoke(ctx qra.Identity, permission, dst string) error {
	p.RLock()
	defer p.RUnlock()

	userID := ctx.Me()
	log.Printf("Revoke : userID [%v]", userID)

	delete(p.Share, userID)

	return nil
}
