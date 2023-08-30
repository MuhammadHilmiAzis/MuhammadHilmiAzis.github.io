package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		contentType := ctx.GetHeader("Content-Type")
		tokenValue, err := ctx.Cookie("session_token")

		if contentType == "application/json" && err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, model.NewErrorResponse("token is missing"))
			return
		} else if contentType != "application/json" && err != nil {
			ctx.AbortWithStatusJSON(http.StatusSeeOther, model.NewErrorResponse("token is jjj"))
			return
		}

		token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error) {

			return model.JwtKey, nil
		})
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, model.NewErrorResponse("token is invalid"))
			return
		}

		// cast claims interface to mapClaims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, model.NewErrorResponse("unauthorized"))
			return
		}

		// convert map to json then turn it into struct model.Claims
		b, _ := json.Marshal(claims)
		var customClaims model.Claims
		json.Unmarshal(b, &customClaims)

		// set jwt payload to gin context that can be shared within a request
		ctx.Set("email", customClaims.Email)
		ctx.Next()

	})
}
