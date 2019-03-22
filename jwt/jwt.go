package jwt

import (
	"time"
	"github.com/SermoDigital/jose/jws"
	"strings"
	"encoding/base64"
)

type Conf struct {
	Method string // 加密算法
	Key    string // 加密key
	Issuer string // 签发者
	Expire int64  // 签名有效期
}

var conf = Conf{
	Method: "HS256",
	Key:    "sahjdjsgaudsiudhuywge",
	Issuer: "testIssuer",
	Expire: 100,
}

// GetJWT 获取json web token
func GetJWT(data map[string]interface{}) (token string, err error) {
	payload := jws.Claims{}
	for k, v := range data {
		payload.Set(k, v)
	}
	now := time.Now()
	payload.SetIssuer(conf.Issuer)
	payload.SetIssuedAt(now)
	payload.SetExpiration(now.Add(time.Duration(conf.Expire) * time.Minute))
	jwtObj := jws.NewJWT(payload, jws.GetSigningMethod(conf.Method))
	tokenBytes, err := jwtObj.Serialize([]byte(conf.Key))
	if err != nil {
		return
	}
	token = string(tokenBytes)
	return
}

// VerifyJWT 验证json web token
func VerifyJWT(token string) (ret bool, data string, err error) {
	jwtObj, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return
	}
	err = jwtObj.Validate([]byte(conf.Key), jws.GetSigningMethod(conf.Method))
	if err == nil {
		ret = true
		arr := strings.Split(token,".")
		input := arr[1]

		var decodeBytes []byte
		decodeBytes, err = base64.RawStdEncoding.DecodeString(input)
		if err != nil {
			return
		}
		data = string(decodeBytes)
	}
	return
}
