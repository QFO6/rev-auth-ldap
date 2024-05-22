package controllers

import (
	"fmt"
	"strings"
	"time"

	revauthldap "github.com/QFO6/rev-auth-ldap"
	revauthldapmodels "github.com/QFO6/rev-auth-ldap/app/models"
	revmongo "github.com/QFO6/rev-mongo"
	utilsgo "github.com/QFO6/utils-go"

	"github.com/globalsign/mgo/bson"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type Auth struct {
	*revel.Controller
	revmongo.MgoController
}

// Accepts form-data and returns user information on authentication success
func (c *Auth) Authenticate(account string, password string, captchaId string, captcha string) revel.Result {
	res := utilsgo.Response{
		Code:    utilsgo.OK,
		Message: utilsgo.StatusText(utilsgo.OK),
	}

	if account == "" || password == "" {
		res.Code = utilsgo.BAD_REQUEST
		res.Message = "Account and password cannot be empty."
		return c.RenderJSON(res)
	}

	loginLog := new(revauthldapmodels.LoginLog)
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr

	captchaEnable := revel.Config.BoolDefault("captcha.enable", false)
	adminUsersStr := revel.Config.StringDefault("admin.users", "e0445226")
	e2eTestUser := strings.ToLower(revel.Config.StringDefault("e2e.test.login.account", ""))
	adminUsers := utilsgo.RemoveBlankStrings(utilsgo.Split(strings.ToLower(adminUsersStr)))

	loginUser := new(revauthldapmodels.User)
	loginIdentity := strings.ToLower(account)
	if loginIdentity == e2eTestUser {
		e2eTestUserPw := revel.Config.StringDefault("e2e.test.login.password", "")
		if e2eTestUserPw == "" || strings.TrimSpace(e2eTestUserPw) == "" {
			res.Code = utilsgo.BAD_REQUEST
			res.Message = "No valid e2e test user password found, please contact with system administrator."
			return c.RenderJSON(res)
		}
		if password != e2eTestUserPw {
			res.Code = utilsgo.LOGIN_FAILED
			res.Message = "Invalid e2e test account password, please contact with system administrator."
			return c.RenderJSON(res)
		}

		loginLog.Account = loginIdentity
		loginUser.Identity = loginIdentity
		fmt.Printf("Login the e2e test account: %v", loginIdentity)
	} else {
		if captchaEnable && captchaId != "" && captcha != "" {
			if !captchaStore.Verify(captchaId, captcha, true) {
				loginLog.Status = "FAILURE"
				revmongo.New(c.MgoSession, loginLog).Create()
				res.Code = utilsgo.BAD_REQUEST
				res.Message = "Wrong captcha, please correct it and try again."
				return c.RenderJSON(res)
			}
		}

		authReply := revauthldap.Authenticate(account, password)
		loginIdentity = strings.ToLower(authReply.Account) // ID returned from grpcldap service
		loginLog.Account = loginIdentity
		loginUser.Identity = loginIdentity

		// authentication failed
		if !authReply.IsAuthenticated {
			loginLog.Status = "FAILURE"
			revmongo.New(c.MgoSession, loginLog).Create()
			res.Code = utilsgo.LOGIN_FAILED
			res.Message = authReply.Error
			return c.RenderJSON(res)
		}

		revmongo.New(c.MgoSession, loginLog).Create()

		loginUser.Mail = authReply.Email
		loginUser.Avatar = authReply.Avatar
		loginUser.Name = authReply.Name
		loginUser.First = authReply.First
		loginUser.Last = authReply.Last
		loginUser.Depart = authReply.Depart
		if loginUser.IsAdmin == false && utilsgo.StrInSlice(loginUser.Identity, adminUsers) {
			loginUser.IsAdmin = true
		}

		// save authorized user information to db by calling SaveUser defined in revauth
		go func(user *revauthldapmodels.User) {
			s := revmongo.NewMgoSession()
			defer s.Close()

			err := user.SaveUser(s)
			if err != nil {
				revel.AppLog.Errorf("Save user error: %v", err)
			}
		}(loginUser)
	}

	// save the user identity in the session
	// HttpOnly flag is set to true by default; Expiration is set to 24h and could be configured via session.expires
	c.Session["IsAdmin"] = loginUser.IsAdmin
	c.Session["UserName"] = strings.TrimSpace(loginUser.Name)
	c.Session["Email"] = strings.TrimSpace(strings.ToLower(loginUser.Mail))
	c.Session["Identity"] = strings.TrimSpace(strings.ToLower(loginIdentity))

	// cache user information by using session ID as key, DefaultExpiryTime is one hour by default
	// ID() creates a time-based UUID identifying this session
	go cache.Set(c.Session.ID(), loginUser, cache.DefaultExpiryTime)

	res.Data = loginUser
	return c.RenderJSON(res)
}

// Logout, clear session variables and delete the user information from cache
func (c *Auth) Logout() revel.Result {
	c.Session = make(map[string]interface{})
	go cache.Delete(c.Session.ID())

	res := utilsgo.Response{
		Code:    utilsgo.OK,
		Message: utilsgo.StatusText(utilsgo.OK),
	}
	return c.RenderJSON(res)
}

// Checks if the session expired by checking if the user identity is still present
func (c *Auth) CheckLogin() revel.Result {
	res := utilsgo.Response{
		Code:    utilsgo.OK,
		Message: utilsgo.StatusText(utilsgo.OK),
	}
	identity, err := c.Session.Get("Identity")
	fmt.Printf("Time:%s; Identity:%s", time.Now().Format(time.RFC3339), identity)
	if err != nil {
		fmt.Println("Session expired")
		res.Code = utilsgo.SESSION_EXPIRED
		res.Message = utilsgo.StatusText(utilsgo.SESSION_EXPIRED)
		return c.RenderJSON(res)
	}

	user := new(revauthldapmodels.User)

	// get user information from cache by using the session ID retrieved from the cookie
	if err := cache.Get(c.Session.ID(), &user); err != nil {
		fmt.Println("user not found in cache")

		do := revmongo.New(c.MgoSession, user)
		do.Query = bson.M{"Identity": identity.(string)}

		if err := do.GetByQ(); err != nil {
			fmt.Println("no matched account found in db")
			res.Code = utilsgo.LOGIN_FAILED
			res.Message = utilsgo.StatusText(utilsgo.LOGIN_FAILED)
			return c.RenderJSON(res)
		}

		// set the user information in cache
		go cache.Set(c.Session.ID(), user, cache.DefaultExpiryTime)
	}

	c.Session["IsAdmin"] = user.IsAdmin
	res.Data = user
	return c.RenderJSON(res)
}
