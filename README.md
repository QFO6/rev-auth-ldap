# Revel auth module via LDAP server

# Usage:

## Installation

Install module

```
# specific version
go get go get github.com/QFO6/rev-auth-ldap@vx.x.x
# or get latest
go get github.com/QFO6/rev-auth-ldap@master
```

## Setup

Include module in app.conf

```
module.revauthldap=github.com/QFO6/rev-auth-ldap
```

Include module in conf/routes

```
module:revauthldap
```

Needs to define routes in under your revel_app/conf/routes file

```
# Support revel routes redirect
GET    /logout                                          RevAuth.Logout
POST   /logout                                          RevAuth.Logout
POST   /login                                           RevAuth.Authenticate

# Return json response
POST   /api/v1/auth/login                               Auth.Authenticate
GET    /api/v1/auth/logout                              Auth.Logout
GET    /api/v1/auth/login-check                         Auth.CheckLogin
POST   /api/v1/auth/captcha                             Captcha.GetCaptcha
GET    /api/v1/auth/get-token                           CSRF.GetToken
```

Note: only support `mongo 4.x` since the driver limitation, ref github.com/QFO6/rev-mongo -> https://github.com/globalsign/mgo

Add revel config variables to your_revel_app/conf/app.conf file

```
# using grpc
grpcauth.port = ${grpcauth_port}
grpcauth.server = ${grpcauth_server}

# using grpc/grpcs
grpcauth.connect = ${grpcauth_connect}
```

Inject env variables during startup or deployment

```
# using grpc
export grpcauth_port="50051"
export grpcauth_server="abc.test.com"
# or same as below
export grpcauth_connect="grpc://abc.test.com:50051"

# using grpcs
export grpcauth_connect="grpcs://abc.test.com:50052"
```

## Setup E2E Test Login

Include revel config variables in Revel Application file conf/app.conf

```
e2e.test.login.account=xxxxxxxxxxxx
e2e.test.login.password=xxxxxxxxxxxx
```

