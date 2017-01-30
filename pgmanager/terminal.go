// Package pgmanager contains a QRA manager for PostgreSQL.
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
package pgmanager

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

// Terminal starts an infinite loop to read the user's input.
func Terminal(driver, connectURL string) error {
	if err := connectAndRegister(driver, connectURL); err != nil {
		return err
	}

	ost, err := terminal.MakeRaw(0)
	if err != nil {
		return err
	}
	defer func() {
		err := terminal.Restore(0, ost)
		if err != nil {
			log.Printf("Terminal : terminal restore : err [%s]", err)
		}
	}()

	// create temporal file for log output

	f, err := ioutil.TempFile(".", "qra_pgmanager_terminal.log")
	if err != nil {
		log.Printf("Terminal : create temporal log : err [%s]", err)
		return err
	}
	log.SetOutput(f)
	fmt.Printf("temporal log file: %s \r\n", f.Name())

	defer func() {
		err := f.Close()
		if err != nil {
			log.Printf("Terminal : close temporal log : err [%s]", err)
		}
		err = os.Remove(f.Name())
		if err != nil {
			log.Printf("Terminal : close temporal log : err [%s]", err)
		}

		// return log to stdout
		log.SetOutput(os.Stdout)
	}()

	// this represents user in terminal
	ctx := &Context{}

	term := terminal.NewTerminal(os.Stdin, "Help [:h] Quit [:q]\n\rUsername:\n\r")
	for {
		l, err := term.ReadLine()
		if err != nil {
			log.Printf("Error read line : err [%s]", err)
			return err
		}

		// prefix indicates action.
		var prefix string
		if len(l) > 1 {
			prefix = l[:2]
		}

		switch prefix {
		case ":q":
			return nil
		case "1:":
			x := strings.Split(l, ":")
			if len(x) != 2 {
				fmt.Printf("Write '1:identity'.\n\r")
				continue
			}

			err = designation.Search(ctx, nil, "identity-create:*")
			if err != nil {
				log.Printf("search : err [%s]", err)
				fmt.Printf("You don't have 'identity-create' permission.\n\r")
				continue
			}

			p, err := term.ReadPassword("Write password for the new identity\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password")
				continue
			}

			_, err = makeUser(x[1], p)
			if err != nil {
				log.Printf("can't create identity : err [%s]", err)
				fmt.Printf("Can't create identity. Password must be equal or greater than 8 characters\n\r")
				continue
			}
			fmt.Printf("New Identity created: %s\n\r", x[1])
			term.SetPrompt(ctx.Username + ":\n\r")
		case "2:":

			x := strings.Split(l, ":")
			log.Printf("x [%v]", x)
			if len(x) != 4 {
				fmt.Printf("Invalid format. Must be '2:identity:permission:resource'.\n\r")
				continue
			}

			p, err := term.ReadPassword("Password\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password : err [%s]", err)
				continue
			}

			// one month permission.
			expiresAt := time.Now().UTC().Add(24 * time.Hour * 30)

			err = designation.Allow(ctx, p, x[2], x[3], x[1], expiresAt)
			if err != nil {
				log.Printf("revoke : err [%s]", err)
				fmt.Printf("Can't share permission\n\r")
				continue
			}
			fmt.Printf("New permission shared\n\r")
			term.SetPrompt(ctx.Username + ":\n\r")
		case "3:":

			x := strings.Split(l, ":")
			log.Printf("x [%v]", x)
			if len(x) != 4 {
				fmt.Printf("Invalid format. Must be '3:identity:permission:resource'.\n\r")
				continue
			}

			p, err := term.ReadPassword("Password\n\r")
			if err != nil {
				log.Printf("read password : err [%s]", err)
				fmt.Printf("Can't read password : err [%s]", err)
				continue
			}

			err = designation.Revoke(ctx, p, x[2], x[3], x[1])
			if err != nil {
				log.Printf("revoke : err [%s]", err)
				fmt.Printf("Can't revoke permission\n\r")
				continue
			}
			fmt.Printf("Permission removed\n\r")
			term.SetPrompt(ctx.Username + ":\n\r")
		case ":h":
			fmt.Printf("\n\rCreate identity [1:<identity>]")
			fmt.Printf("\n\rShare permission [2:<identity>:<permission>:<resource>]")
			fmt.Printf("\n\rRevoke permission [3:<identity>:<permission>:<resource>]")
			fmt.Printf("\n\rLogout [:5]\n\r")
		case ":5":
			err := authentication.Close(ctx)
			if err != nil {
				fmt.Printf("Can't close session.\n\r")
				continue
			}
			fmt.Printf("Session closed.\n\r")
			term.SetPrompt("Help [:h] Quit [:q]\n\rUsername:\n\r")
			ctx.Username = ""
			ctx.Token = ""
		default:

			// Login process.
			if len(ctx.Token) < 1 {
				if ctx.Username == "" && len(l) > 0 {
					ctx.Username = l

					p, err := term.ReadPassword("Write password:\n\r")
					if err != nil {
						fmt.Printf("Can't read password : err [%s]", err)
						ctx.Username = ""
						continue
					}

					// authentication

					err = authentication.Authenticate(ctx, p, &ctx.Token)
					if err != nil {
						fmt.Printf("Invalid username or password\n\r")
						ctx.Username = ""
						continue
					}

					// session on terminal permission validation.

					err = designation.Search(ctx, nil, "session-on:terminal")
					if err != nil {
						fmt.Printf("You don't have allowed terminal sessions\n\r")
						err = authentication.Close(ctx)
						if err != nil {
							log.Printf("Close session err [%s]", err)
						}
						ctx.Username = ""
						ctx.Token = ""
						continue
					}

					term.SetPrompt(ctx.Username + ":\n\r")
				}
			}
		}
	}
}
