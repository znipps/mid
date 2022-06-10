package middleware

import (
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db/dao"
	"net/http"
	"time"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/errno"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"

	"github.com/gin-gonic/gin"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/utils"
)

func checkAuth(username, password string) (int32, error) {
	record, err := dao.GetUserRecord(username, password)
	if err != nil {
		log.Error(err)
		return 0, err
	}
	if len(record) > 0 {
		return record[0].ID, nil
	}
	return 0, err
}

// JWTMiddleWare 中间件
func JWTMiddleWare(c *gin.Context) {
	code := errno.OK
	strToken := c.Request.Header.Get("Authorization")
	token := utils.GetToken(strToken)
	log.Debugf("jwt[%s]", token)

	var err error
	var claims *utils.Claims

	if token == "" {
		username := c.Query("username")
		password := c.Query("password")
		if username == "" || password == "" {
			log.Error(err.Error())
			c.JSON(http.StatusOK, errno.ErrNotAuthorized)
			c.Abort()
			return
		}

		_, err := checkAuth(username, password)

		if err != nil {
			log.Error(err.Error())
			code = errno.ErrNotAuthorized
		} else {
			code = errno.OK
		}

	} else {
		claims, err = utils.ParseToken(token)
		if err != nil {
			code = errno.ErrAuthTokenErr
		} else if time.Now().Unix() > claims.ExpiresAt.Unix() {
			code = errno.ErrAuthTimeout
		}
	}

	if code != errno.OK {
		c.JSON(http.StatusOK, code)
		c.Abort()
		return
	}

	if token != "" {
		log.Debugf("id:%s UserName:%s", claims.ID, claims.UserName)
		c.Set("jwt", claims)
	}

	c.Next()
}
