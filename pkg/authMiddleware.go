package authMiddleware

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type UserInfo struct {
	UserId      string   `json:"sub"`
	Permissions []string `json:"permissions"`
}
type AuthMiddleware struct {
	Domain string
}

func NewAuthMiddleware(domain string) (*AuthMiddleware, error) {
	return &AuthMiddleware{
		Domain: domain,
	}, nil
}

func (authMiddleware *AuthMiddleware) getUserInfo(token string) (*UserInfo, error) {
	userBearerToken := fmt.Sprintf("Bearer %s", token)
	userInfoEndpoint := fmt.Sprintf("https://%s/userinfo", authMiddleware.Domain)
	request, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Authorization", userBearerToken)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var userData UserInfo
	userDataDecoder := json.NewDecoder(response.Body)
	err = userDataDecoder.Decode(&userData)
	if err != nil {
		return nil, err
	}

	return &userData, nil
}
