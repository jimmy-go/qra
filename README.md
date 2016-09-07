####Quick and Robust Admin interface written in Go

[![License MIT](https://img.shields.io/npm/l/express.svg)](http://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/jimmy-go/qra.svg?branch=master)](https://travis-ci.org/jimmy-go/qra)
[![Go Report Card](https://goreportcard.com/badge/github.com/jimmy-go/qra)](https://goreportcard.com/report/github.com/jimmy-go/qra)
[![GoDoc](http://godoc.org/github.com/jimmy-go/qra?status.png)](http://godoc.org/github.com/jimmy-go/qra)
[![Coverage Status](https://coveralls.io/repos/github/jimmy-go/qra/badge.svg?branch=master)](https://coveralls.io/github/jimmy-go/qra?branch=master)

QRA is a collection of interfaces for common tasks building
admin sites.

![diagram](diagram.png)

#####Installation:
```
go get gopkg.in/jimmy-go/qra.v0
```

#####Usage:

QRA has a default manager, you can add doers with:
```
qra.MustRegisterSessioner(yourSessioner)
qra.MustRegisterAccounter(yourAccounter)
qra.MustRegisterRoler(yourRoler)
qra.MustRegisterPermissioner(yourPermissioner)
qra.MustRegisterActioner(yourActioner)
```

Inside your project call some qra function.
```
func MyLoginHandler(w http.Response, r *http.Request) {

    // this will call qra.DefaultManager.Session.Login method.
    err := qra.Login("someuser","somepass")
    // check errors...
}
```

#####One more thing...
QRA has a collection of managers with several database integrations:

`qra/litemanager.Connect("sqlite", "url://somedatabasefile.sql")` registers a manager
with sqlite integration.

`qra/pgmanager.Connect("postgres", "url://somedatabasefile.sql")` registers a manager
with PostgreSQL integration.

`qra/rawmanager.Connect()` is a manager with only cache data (never use it on production,
demonstration purposes only).

See the [QRA examples](https://github.com/jimmy-go/qra-examples) for real world usage.

#####License:

MIT License

Copyright (c) 2016 Angel Del Castillo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
