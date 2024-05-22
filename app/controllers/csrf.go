package controllers

import (
	"github.com/revel/revel"
)

type CSRF struct {
	*revel.Controller
}

// Returns the CSRF token associated with the user's current session
func (c *CSRF) GetToken() revel.Result {
	output := map[string]interface{}{
		"csrfToken": c.Session["csrf_token"],
	}
	return c.RenderJSON(output)
}
