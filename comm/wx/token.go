package wx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db/dao"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/db/model"
)

type DataForm struct {
	RequestType string   `json:"type"`
	Request     *Request `json:"request"`
	AccesToken  string   `json:"token"`
}

type Request struct {
	Data *NotifyToken `json:"data"`
}

type NotifyToken struct {
	Appid     string `json:"appid"`
	Token     string `json:"token"`
	TokenType int    `json:"token_type"`
}

func getAccessTokenWithRetry(appid string, tokenType int) (string, error) {
	var token string
	var err error
	for i := 0; i < 3; i++ {
		if token, err = getAccessToken(appid, tokenType); err != nil {
			log.Error(err)
			if err.Error() == "lock fail" {
				time.Sleep(200 * time.Millisecond)
				continue
			}
		}
		break
	}

	log.Infof("token {%s}, appid {%s}, tokenType {%d}", token, appid, tokenType)

	notifyCallback(token, appid, tokenType)

	return token, err
}

func makeTokenNotifyDataForm(token, appid string, tokenType int) DataForm {
	return DataForm{
		RequestType: "saveToken",
		Request: &Request{
			Data: &NotifyToken{
				Appid:     appid,
				Token:     token,
				TokenType: tokenType,
			},
		},
	}
}

func notifyCallback(token, appid string, tokenType int) {
	searchType := "component"
	if tokenType == model.WXTOKENTYPE_AUTH {
		searchType = "authorizer"
	} else if tokenType == model.WXTOKENTYPE_OWN {
		searchType = "component"
	}

	rules, err := dao.GetWxCallBackRulesWithCache("token-callback", searchType, "")

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

				notifyToken := makeTokenNotifyDataForm(token, appid, tokenType)

				jsonBytes, err := json.Marshal(&notifyToken)

				resp, err := http.Post(proxyConfig.Path, "application/json", bytes.NewBuffer(jsonBytes))

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

func getAccessToken(appid string, tokenType int) (string, error) {
	// ?????????
	cacheCli := db.GetCache()
	cacheKey := genTokenKey(appid, tokenType)
	if value, found := cacheCli.Get(cacheKey); found {
		log.Info("hit cache, token: ", value)
		return value.(string), nil
	}

	// ????????????
	record, found, err := dao.GetAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}
	cacheDuration := 5 * time.Minute
	if found && record.Expiretime.After(time.Now()) {
		// ????????????????????????
		if d, _ := time.ParseDuration("5m"); record.Expiretime.Before(time.Now().Add(d)) {
			// 5min????????? ???1/100???????????????
			if rand.Seed(time.Now().UnixNano()); rand.Intn(100) == 0 {
				go updateAccessToken(appid, tokenType)
			}
			// ??????????????????????????????
			cacheDuration = time.Until(record.Expiretime)
		}
		// ?????????
		cacheCli.Set(cacheKey, record.Token, cacheDuration)
		return record.Token, nil
	}
	// ???????????? ????????????
	token, err := updateAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}
	// ?????????
	cacheCli.Set(cacheKey, token, cacheDuration)
	return token, err
}

func updateAccessToken(appid string, tokenType int) (string, error) {
	// ??????
	lockKey := genTokenLockKey(appid, tokenType)
	if err := dao.Lock(lockKey, gUniqueId, 10*time.Second); err != nil {
		log.Error(err)
		return "", errors.New("lock fail")
	}
	// ??????????????????
	defer dao.UnLock(lockKey)

	// ?????????token
	token, err := getNewAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}

	// ???????????????
	dao.SetAccessToken(&model.WxToken{
		Type:       tokenType,
		Appid:      appid,
		Token:      token,
		Expiretime: time.Now().Add(2 * time.Hour).Add(-time.Minute),
	})
	return token, nil
}

func getNewAccessToken(appid string, tokenType int) (string, error) {
	if tokenType == model.WXTOKENTYPE_AUTH {
		return getNewAuthorizerAccessToken(appid)
	} else if tokenType == model.WXTOKENTYPE_OWN {
		return getNewComponentAccessToken()
	}
	return "", errors.New("invalid type")
}

func genTokenKey(appid string, tokenType int) string {
	return fmt.Sprintf("Token_%d_%s", tokenType, appid)
}

func genTokenLockKey(appid string, tokenType int) string {
	return fmt.Sprintf("TLock_%d_%s", tokenType, appid)
}

var gUniqueId string

func init() {
	const char = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	rand.NewSource(time.Now().UnixNano()) // ??????????????????
	var s bytes.Buffer
	for i := 0; i < 8; i++ {
		s.WriteByte(char[rand.Int63()%int64(len(char))])
	}
	gUniqueId = s.String()
	log.Info("gUniqueId: ", gUniqueId)
}
