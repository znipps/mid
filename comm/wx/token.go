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
	// 读缓存
	cacheCli := db.GetCache()
	cacheKey := genTokenKey(appid, tokenType)
	if value, found := cacheCli.Get(cacheKey); found {
		log.Info("hit cache, token: ", value)
		return value.(string), nil
	}

	// 读数据库
	record, found, err := dao.GetAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}
	cacheDuration := 5 * time.Minute
	if found && record.Expiretime.After(time.Now()) {
		// 找到未超时的记录
		if d, _ := time.ParseDuration("5m"); record.Expiretime.Before(time.Now().Add(d)) {
			// 5min后超时 按1/100的概率刷新
			if rand.Seed(time.Now().UnixNano()); rand.Intn(100) == 0 {
				go updateAccessToken(appid, tokenType)
			}
			// 缓存时间设为过期时间
			cacheDuration = time.Until(record.Expiretime)
		}
		// 写缓存
		cacheCli.Set(cacheKey, record.Token, cacheDuration)
		return record.Token, nil
	}
	// 没有数据 重新获取
	token, err := updateAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}
	// 写缓存
	cacheCli.Set(cacheKey, token, cacheDuration)
	return token, err
}

func updateAccessToken(appid string, tokenType int) (string, error) {
	// 抢锁
	lockKey := genTokenLockKey(appid, tokenType)
	if err := dao.Lock(lockKey, gUniqueId, 10*time.Second); err != nil {
		log.Error(err)
		return "", errors.New("lock fail")
	}
	// 返回前释放锁
	defer dao.UnLock(lockKey)

	// 请求新token
	token, err := getNewAccessToken(appid, tokenType)
	if err != nil {
		log.Error(err)
		return "", err
	}

	// 写入数据库
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

	rand.NewSource(time.Now().UnixNano()) // 产生随机种子
	var s bytes.Buffer
	for i := 0; i < 8; i++ {
		s.WriteByte(char[rand.Int63()%int64(len(char))])
	}
	gUniqueId = s.String()
	log.Info("gUniqueId: ", gUniqueId)
}
