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
	"log"
	"sync"

	"github.com/jimmy-go/qra"
	"github.com/satori/go.uuid"
)

var (
	errInvalidCredentials = errors.New("raw session: invalid username or password")
)

// Authenticationer struct
type Authenticationer struct {
	Data  map[string]string
	Users map[string]string

	sync.RWMutex
}

// Authenticate makes login for Identity.
func (s *Authenticationer) Authenticate(ctx qra.Identity, password string, dst interface{}) error {
	s.RLock()
	defer s.RUnlock()

<<<<<<< HEAD:rawmanager/session.go
	log.Printf("Session : u [%s] p [%s]", u, p)

	pass, ok := users[u]
	if !ok {
		return errUserNotFound
	}
	if pass != p {
		return errUserNotFound
	}
	return nil
}

// Locate func.
func (s *Session) Locate(sessionID string) (interface{}, error) {
	s.RLock()
	defer s.RUnlock()

	log.Printf("Locate : sessionID [%s]", sessionID)

	v, ok := s.Data[sessionID]
	if !ok {
		return "", errSessionNotFound
	}

	return v, nil
=======
	userID := ctx.Me()
	log.Printf("Authenticate : userID [%s]", userID)

	pass, ok := s.Users[userID]
	if !ok || pass != password {
		return errInvalidCredentials
	}

	s.Data[userID] = uuid.NewV4().String()
	return nil
>>>>>>> release/v0.0.2:rawmanager/authentication_manager.go
}

// Close deletes current session of Identity.
func (s *Authenticationer) Close(ctx qra.Identity) error {
	s.RLock()
	defer s.RUnlock()

	userID := ctx.Me()
	log.Printf("Close : userID [%s]", userID)

	var sessionID string
	err := ctx.Session(&sessionID)
	if err != nil {
		log.Printf("Close : get session : err [%s]", err)
		return err
	}

	log.Printf("Delete : sessionID [%s]", sessionID)

	delete(s.Data, sessionID)
	return nil
}
