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
	sessions    *Session
	accounts    *Account
	roles       *Role
	permissions *Permission
	actions     *Action
)

// Connect starts the manager.
// In most common cases here you start third party connections
// as databases, clients, etc.
func Connect() error {
	sessions = &Session{
		Data: make(map[string]string),
		// users simulates database user validation.
		// user:password key set.
		Users: map[string]string{
			"admin@mail.com": "admin123",
			"user1@mail.com": "123456",
			"user2@mail.com": "abcdef",
		},
	}
	accounts = &Account{
		// Data is a collection of accounts created on the way.
		// a real qra-manager can has access to database.
		Data: make(map[string]string),
	}
	roles = &Role{
		Data:       make(map[string]string),
		Collection: []string{"admin", "user"},
		// roles by users.
		Users: map[string][]string{
			"admin@mail.com": []string{"admin", "user"},
			"user1@mail.com": []string{"user"},
			"user2@mail.com": []string{"user", "blank"},
		},
	}
	permissions = &Permission{
		// Data contains user and resourceID where he can edit.
		Data: map[string][]string{
			// admin can edit himself and user1 and user2.
			"admin@mail.com": []string{
				"admin@mail.com",
				"user1@mail.com",
				"user2@mail.com",
			},
			// user1 has permissions over himself only.
			"user1@mail.com": []string{
				"user1@mail.com",
			},
			// user2 has permissions over himself only.
			"user2@mail.com": []string{
				"user2@mail.com",
			},
		},
	}
	actions = &Action{
		// Data contains user and his allowed actions.
		Data: map[string][]string{
			// admin can create, edit or delete users.
			"admin@mail.com": []string{
				"user-create",
				"user-edit",
				"user-delete",
			},
			// user1 has allowed edit users, create, edit
			// and delete checklist items.
			"user1@mail.com": []string{
				"user-edit",
				"checklist-create",
				"checklist-edit",
				"checklist-delete",
			},
			// user2 has allowed edit users, create, edit
			// and delete checklist items.
			"user2@mail.com": []string{
				"user-edit",
				"checklist-create",
				"checklist-edit",
				"checklist-delete",
			},
		},
	}

	//	log.Printf("RawManager : sessions [%v]", sessions)
	//	log.Printf("RawManager : accounts [%v]", accounts)
	//	log.Printf("RawManager : roles [%v]", roles)
	//	log.Printf("RawManager : permissions [%v]", permissions)
	//	log.Printf("RawManager : actions [%v]", actions)

	// register qra default manager or panics.
	qra.MustRegisterSessioner(sessions)
	qra.MustRegisterAccounter(accounts)
	qra.MustRegisterRoler(roles)
	qra.MustRegisterPermissioner(permissions)
	qra.MustRegisterActioner(actions)
	return nil
}
