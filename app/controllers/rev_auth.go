package controllers

import (
	"fmt"
	"strings"

	revauthldap "github.com/QFO6/rev-auth-ldap"
	revauthldapmodels "github.com/QFO6/rev-auth-ldap/app/models"
	revmongo "github.com/QFO6/rev-mongo"

	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type RevAuth struct {
	*revel.Controller
	revmongo.MgoController
}

// Authenticate for LDAP authenticate and redirect with revel route
func (c *RevAuth) Authenticate(account, password string) revel.Result {
	//get nextUrl
	nextUrl := c.Params.Get("nextUrl")
	if nextUrl == "" {
		nextUrl = "/"
	}

	if account == "" || password == "" {
		c.Flash.Error("Please fill in account and password")
		return c.Redirect(c.Request.Referer())
	}

	loginUser := new(revauthldapmodels.User)
	loginLog := new(revauthldapmodels.LoginLog)
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr

	loginIdentity := strings.ToLower(account) // ID returned from grpcldap service

	e2eTestUser := strings.ToLower(revel.Config.StringDefault("e2e.test.login.account", ""))

	if loginIdentity == e2eTestUser {
		e2eTestUserPw := revel.Config.StringDefault("e2e.test.login.password", "")
		if e2eTestUserPw == "" || strings.TrimSpace(e2eTestUserPw) == "" {
			c.Flash.Error("No valid e2e test user password found, please contact with system administrator.")
			return c.Redirect("/login?nextUrl=%s", nextUrl)
		}
		if password != e2eTestUserPw {
			c.Flash.Error("Invalid e2e test account password, please contact with system administrator.")
			return c.Redirect("/login?nextUrl=%s", nextUrl)
		}

		loginLog.Account = loginIdentity
		loginUser.Identity = loginIdentity
		fmt.Printf("Login the e2e test account: %v", loginIdentity)
	} else {
		// account can be ID or mail
		authUser := revauthldap.Authenticate(account, password)
		loginIdentity = strings.ToLower(authUser.Account) // ID returned from grpcldap service
		loginLog.Account = loginIdentity
		if !authUser.IsAuthenticated {
			loginLog.Status = "FAILURE"
			revmongo.New(c.MgoSession, loginLog).Create()

			c.Flash.Error("Authenticate failed with error: %v", authUser.Error)
			return c.Redirect(c.Request.Referer())
		}

		loginUser.Identity = loginIdentity
		loginUser.Mail = authUser.Email
		loginUser.Avatar = authUser.Avatar
		loginUser.Name = authUser.Name
		loginUser.Depart = authUser.Depart
		loginUser.First = authUser.First
		loginUser.Last = authUser.Last

		go func(user *revauthldapmodels.User) {
			// save to local user
			s := revmongo.NewMgoSession()
			defer s.Close()
			err := user.SaveUser(s)
			if err != nil {
				revel.AppLog.Errorf("Save user error: %v", err)
			}

		}(loginUser)
	}

	revmongo.New(c.MgoSession, loginLog).Create()

	c.Session["UserName"] = strings.TrimSpace(loginUser.Name)
	c.Session["Email"] = strings.TrimSpace(strings.ToLower(loginUser.Mail))
	c.Session["Identity"] = strings.TrimSpace(strings.ToLower(loginIdentity))

	go cache.Set(c.Session.ID(), loginUser, cache.DefaultExpiryTime)

	c.Flash.Success("Welcome, %v", loginUser.Name)
	return c.Redirect(nextUrl)
}

// Logout
func (c *RevAuth) Logout() revel.Result {
	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())

	c.Session = make(map[string]interface{})
	c.Flash.Success("You have logged out.")
	return c.Redirect("/")
}
