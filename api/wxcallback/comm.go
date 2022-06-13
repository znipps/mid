package wxcallback

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/errno"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db/dao"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db/model"
	"github.com/gin-gonic/gin"
)

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = target.Path
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}
	errorHandler := func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Errorf("http: proxy error: %v", err)
		result, _ := json.Marshal(errno.ErrSystemError.WithData(err.Error()))
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(result))
	}
	return &httputil.ReverseProxy{Director: director, ErrorHandler: errorHandler}
}

func proxyCallbackMsg(infoType string, msgType string, event string, body string, c *gin.Context) (bool, error) {
	rule, err := dao.GetWxCallBackRuleWithCache(infoType, msgType, event)
	if err != nil {
		log.Error(err)
		return false, err
	}
	if rule != nil && rule.Open != 0 && rule.Type == model.PROXYTYPE_HTTP {
		var proxyConfig model.HttpProxyConfig
		if err = json.Unmarshal([]byte(rule.Info), &proxyConfig); err != nil {
			log.Errorf("Unmarshal err, %v", err)
			return false, err
		}
		path := strings.Replace(proxyConfig.Path, "$APPID$", c.Param("appid"), -1)
		log.Infof("proxy: %v, real path %s", rule, path)
		var target *url.URL
		if target, err = url.Parse(fmt.Sprintf("http://127.0.0.1:%d%s", proxyConfig.Port, path)); err != nil {
			log.Errorf("url Parse error: %v", err)
			return false, err
		}
		proxy := newReverseProxy(target)
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
		proxy.ServeHTTP(c.Writer, c.Request)
		return true, nil
	}
	return false, nil
}

func notify(infoType string, msgType string, event string, body string, c *gin.Context) {
	rules, err := dao.GetWxCallBackRulesWithCache(infoType, msgType, event)

	if err != nil {
		log.Error(err)
		return
	}

	//TODO invoke goroutine?
	for _, rule := range rules {
		if rule.Open != 0 && rule.Type == model.INVOKE_HTTP {
			func() {
				var proxyConfig model.HttpProxyConfig
				if err = json.Unmarshal([]byte(rule.Info), &proxyConfig); err != nil {
					log.Errorf("Unmarshal err, %v", err)
					return
				}

				resp, err := http.Post(proxyConfig.Path, "application/json", bytes.NewBufferString(body))

				if err != nil {
					log.Errorf("Invoke token call back error", err)
					return
				}

				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					log.Errorf("Non-OK HTTP status: %d", resp.StatusCode)
					return
				}

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Errorf("Read body error")
					return
				}

				log.Infof("Get response : %s", body)
			}()
		}
	}
}

func triggerToken(infoType string, c *gin.Context) {
	rule, err := dao.GetWxCallBackRuleWithCache("trigger", "token-trigger", infoType)

	if err != nil {
		log.Error(err)
	}

	if rule != nil && rule.Open != 0 && rule.Type == model.INVOKE_HTTP {
		var proxyConfig model.HttpProxyConfig
		if err = json.Unmarshal([]byte(rule.Info), &proxyConfig); err != nil {
			log.Errorf("Unmarshal err, %v", err)
			return
		}

		path := strings.Replace(proxyConfig.Path, "$APPID$", c.Param("appid"), -1)
		log.Infof("proxy: %v, real path %s", rule, path)
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s", proxyConfig.Port, path))

		if err != nil {
			log.Errorf("Invoke token call back error", err)
			return
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Errorf("Non-OK HTTP status: %d", resp.StatusCode)
			return
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Read body error")
			return
		}

		log.Infof("Get response : %s", body)
	}
}
