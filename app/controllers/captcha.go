package controllers

import (
	"fmt"

	"github.com/mojocn/base64Captcha"
	"github.com/revel/revel"

	utilsgo "github.com/QFO6/utils-go"
)

type Captcha struct {
	*revel.Controller
}

var captchaStore = base64Captcha.DefaultMemStore

func (c *Captcha) GetCaptcha(account string, password string) revel.Result {
	fmt.Printf("Get captcha for username:%s; password:%s", account, password)

	imgWidth := revel.Config.IntDefault("captcha.width", 240)
	imgHeight := revel.Config.IntDefault("captcha.height", 80)
	keyLong := revel.Config.IntDefault("captcha.key.long", 6)

	driver := base64Captcha.NewDriverDigit(imgHeight, imgWidth, keyLong, 0.7, 80)
	captcha := base64Captcha.NewCaptcha(driver, captchaStore)

	if id, b64s, err := captcha.Generate(); err != nil {
		revel.AppLog.Errorf("%v", err)
		res := utilsgo.Response{
			Code:    utilsgo.BAD_REQUEST,
			Message: "Generate captcha failed",
		}
		return c.RenderJSON(res)
	} else {
		res := utilsgo.Response{
			Code:    utilsgo.OK,
			Message: "",
			Data: map[string]interface{}{
				"picPath":   b64s,
				"captchaId": id,
			},
		}
		return c.RenderJSON(res)
	}
}
