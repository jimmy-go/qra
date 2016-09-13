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

import "github.com/jimmy-go/qra"

var (
	authentication *Authenticationer
	designation    *Designationer
)

// Connect starts the manager.
// In most common cases here you start third party connections
// as databases, clients, etc.
func Connect() error {
	authentication = &Authenticationer{
		Data: make(map[string]string),
		// users simulates database user validation.
		// user:password key set.
		Users: map[string]string{
			"admin@mail.com": "admin123",
			"user1@mail.com": "123456",
			"user2@mail.com": "abcdef",
		},
	}
	designation = &Designationer{
		// Data contains user and resourceID where he can edit.
		Data: map[string][]string{
			// admin can edit himself and user1 and user2.
			"admin@mail.com": []string{
				"read:admins",
				"read:users",
				"read:admin@mail.com",
				"write:admin@mail.com",
				"read:user1@mail.com",
				"read:user2@mail.com",
			},
			// user1 has permissions over himself only.
			"user1@mail.com": []string{
				"read:users",
				"read:user1@mail.com",
				"write:user1@mail.com",
			},
			// user2 has permissions over himself only.
			"user2@mail.com": []string{
				"read:users",
				"read:user2@mail.com",
				"write:user2@mail.com",
			},
		},
		// Share it permissions.
		Share: map[string]string{
			"admin@mail.com": "user2@mail.com",
		},
	}

	qra.MustRegisterAuthentication(authentication)
	qra.MustRegisterDesignation(designation)
	return nil
}
