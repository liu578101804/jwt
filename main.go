package main

import (
	"github.com/liu578101804/jwt/jwt"
	"fmt"
)

func main() {
	data := map[string]interface{}{
		"id": "1",
		"name": "张三",
	}
	token, err := jwt.GetJWT(data)
	if err != nil {
		fmt.Println(err)
	}

	isOk, rdata, err := jwt.VerifyJWT(token)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(isOk, rdata)

}
