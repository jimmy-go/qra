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

	"github.com/satori/go.uuid"
)

var (
	errSessionNotFound = errors.New("raw session: session not found")
	errUserNotFound    = errors.New("raw session: user not found")
	errInvalidUserID   = errors.New("raw session: invalid user id")
)

// Session struct
type Session struct {
	Data  map[string]string
	Users map[string]string

	sync.RWMutex
}

// ImplementsSessioner satisfies Sessioner.
func (s *Session) ImplementsSessioner() {}

// Login func.
func (s *Session) Login(u, p string) error {
	s.RLock()
	defer s.RUnlock()

	log.Printf("Session : u [%s] p [%s]", u, p)
	pass, ok := s.Users[u]
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

	v, ok := s.Data[sessionID]
	if !ok {
		return "", errSessionNotFound
	}

	log.Printf("Locate : sessionID [%s]", sessionID)
	if len(v) < 1 {
		return "", errSessionNotFound
	}
	return v, nil
}

// Create func.
func (s *Session) Create(userID string) (string, error) {
	s.RLock()
	defer s.RUnlock()

	log.Printf("Create : userID [%s]", userID)

	if len(userID) < 1 {
		return "", errInvalidUserID
	}

	s.Data[userID] = uuid.NewV4().String()
	return s.Data[userID], nil
}

// Delete func.
func (s *Session) Delete(sessionID string) error {
	s.RLock()
	defer s.RUnlock()

	delete(s.Data, sessionID)
	return nil
}
