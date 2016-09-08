// Package qra contains tests for QRA.
// TODO; make test for managers.
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

import "testing"

type RR struct{}

func (r *RR) ImplementsRoler() {}

func (r *RR) List() ([]string, error) {
	return []string{}, nil
}

func (r *RR) Create(name string, data interface{}) error {
	return nil
}

func (r *RR) Delete(name string) error {
	return nil
}

func (r *RR) UserRoles(userID string) ([]string, error) {
	return []string{}, nil
}

func (r *RR) UserHas(userID, roleID string) bool {
	return true
}

func (r *RR) UserRoleAdd(userID, roleID string) error {
	return nil
}

func (r *RR) UserRoleRemove(userID, roleID string) error {
	return nil
}

// TODO;
func TestNew(t *testing.T) {
	roler := &RR{}
	err := RegisterRoler(roler)
	if err != nil {
		t.Logf("err [%s]", err)
		t.Fail()
	}
}
