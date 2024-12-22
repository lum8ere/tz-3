package auth

import (
	"encoding/json"
	"net/http"
	"test-task3/libs/1_domain_methods/helpers"
	"test-task3/libs/2_generated_models/model"
	"test-task3/libs/4_common/smart_context"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

func AuthRoutes(r chi.Router, sctx smart_context.ISmartContext) {
	r.Post("/auth", func(w http.ResponseWriter, r *http.Request) {
		userId := r.URL.Query().Get("userId")
		if userId == "" {
			http.Error(w, "missing userId", http.StatusBadRequest)
			return
		}

		clientIP := helpers.GetClientIP(r)

		accessToken, err := helpers.GenerateJWT(sctx, userId, clientIP)
		if err != nil {
			sctx.Errorf("generateJWT error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Refresh-токен base64
		refreshPlain, err := helpers.GenerateRandomBase64(32)
		if err != nil {
			sctx.Errorf("generateRandomBase64 error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshPlain), bcrypt.DefaultCost)
		if err != nil {
			sctx.Errorf("bcrypt error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newRefresh := model.RefreshToken{
			UserID:      userId,
			HashedToken: string(hashedToken),
			IPAddress:   clientIP,
			Used:        false,
		}

		if err := sctx.GetDB().Save(&newRefresh).Error; err != nil {
			sctx.Errorf("DB error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshPlain,
		}
		writeJSON(w, resp)
	})

	r.Post("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Header.Get("X-Access-Token")
		refreshPlain := r.Header.Get("X-Refresh-Token")

		if accessToken == "" || refreshPlain == "" {
			http.Error(w, "missing tokens", http.StatusBadRequest)
			return
		}

		userId, jwtErr := helpers.ParseJWT(sctx, accessToken)
		if jwtErr != nil {
			sctx.Errorf("parseJWT error: %v", jwtErr)
			http.Error(w, "invalid access token", http.StatusUnauthorized)
			return
		}

		var ref model.RefreshToken
		if err := sctx.GetDB().Where("user_id = ? AND used = false", userId).Last(&ref).Error; err != nil {
			sctx.Errorf("refresh token not found: %v", err)
			http.Error(w, "refresh token not found", http.StatusUnauthorized)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(ref.HashedToken), []byte(refreshPlain)); err != nil {
			sctx.Errorf("bcrypt compare fail: %v", err)
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}

		if ref.Used {
			sctx.Error("Refresh token already used")
			http.Error(w, "refresh token already used", http.StatusUnauthorized)
			return
		}

		// если IP другой — отправляем mock email (лог в консоль)
		clientIP := helpers.GetClientIP(r)
		if clientIP != ref.IPAddress {
			sctx.Warnf("WARNING: IP changed for user %s. Old IP=%s, new IP=%s", userId, ref.IPAddress, clientIP)
		}

		ref.Used = true
		if err := sctx.GetDB().Save(&ref).Error; err != nil {
			sctx.Errorf("DB error on update refresh token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newAccess, err := helpers.GenerateJWT(sctx, userId, clientIP)
		if err != nil {
			sctx.Errorf("generateJWT error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newRefreshPlain, err := helpers.GenerateRandomBase64(32)
		if err != nil {
			sctx.Errorf("generateRandomBase64 error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(newRefreshPlain), bcrypt.DefaultCost)
		if err != nil {
			sctx.Errorf("bcrypt error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		newRef := model.RefreshToken{
			UserID:      userId,
			HashedToken: string(hashed),
			IPAddress:   clientIP,
			Used:        false,
		}
		if err := sctx.GetDB().Save(&newRef).Error; err != nil {
			sctx.Errorf("DB error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := map[string]string{
			"access_token":  newAccess,
			"refresh_token": newRefreshPlain,
		}
		writeJSON(w, resp)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
