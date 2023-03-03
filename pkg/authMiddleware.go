package authMiddleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slices"
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

func (authMiddleware *AuthMiddleware) RequirePermission(context *gin.Context, permission string) {
	userAuthHeader := context.GetHeader("Authorization")
	userToken := strings.TrimPrefix(userAuthHeader, "Bearer ")

	if userToken == "" {
		context.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	userInfo, err := authMiddleware.getUserInfo(userToken)
	if err != nil {
		context.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if !slices.Contains(userInfo.Permissions, permission) {
		context.AbortWithStatus(http.StatusForbidden)
		return
	}

	context.Next()
}
