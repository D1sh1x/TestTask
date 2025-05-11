package handler

import (
	"auth-service/internal/service"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	tokenService *service.TokenService
}

// Response models for swagger
type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Message string `json:"message"`
}

func NewAuthHandler(tokenService *service.TokenService) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
	}
}

// GetTokens godoc
// @Summary Get access and refresh tokens
// @Description Get a pair of access and refresh tokens for a user
// @Tags auth
// @Accept json
// @Produce json
// @Param user_id query string true "User ID (UUID format)"
// @Success 200 {object} models.TokenPair
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/token [post]
func (h *AuthHandler) GetTokens(c echo.Context) error {
	userIDStr := c.QueryParam("user_id")
	if userIDStr == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "user_id is required"})
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid user_id format"})
	}

	userAgent := c.Request().UserAgent()
	ip := c.RealIP()

	tokens, err := h.tokenService.GenerateTokenPair(userID, userAgent, ip)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, tokens)
}

// RefreshTokens godoc
// @Summary Refresh access and refresh tokens
// @Description Get a new pair of tokens using a refresh token
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param refresh_token formData string true "Refresh token in base64 format"
// @Success 200 {object} models.TokenPair
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/token/refresh [post]
func (h *AuthHandler) RefreshTokens(c echo.Context) error {
	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{Error: "refresh_token is required"})
	}

	userAgent := c.Request().UserAgent()
	ip := c.RealIP()

	tokens, err := h.tokenService.RefreshTokens(refreshToken, userAgent, ip)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, tokens)
}

// GetCurrentUser godoc
// @Summary Get current user information
// @Description Get the current user's ID using an access token
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} ErrorResponse
// @Router /auth/me [get]
func (h *AuthHandler) GetCurrentUser(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "missing authorization header"})
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid authorization header"})
	}

	userID, err := h.tokenService.ValidateAccessToken(tokenParts[1])
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"user_id": userID.String()})
}

// Logout godoc
// @Summary Logout user
// @Description Revoke all refresh tokens for the user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "missing authorization header"})
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid authorization header"})
	}

	userID, err := h.tokenService.ValidateAccessToken(tokenParts[1])
	if err != nil {
		return c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
	}

	err = h.tokenService.RevokeTokens(*userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, SuccessResponse{Message: "logged out successfully"})
}
