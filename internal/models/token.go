package models

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a refresh token stored in the database
// @Description Refresh token information
type RefreshToken struct {
	ID        uuid.UUID `json:"id" db:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	UserID    uuid.UUID `json:"user_id" db:"user_id" example:"123e4567-e89b-12d3-a456-426614174000"`
	TokenHash string    `json:"token_hash" db:"token_hash"`
	UserAgent string    `json:"user_agent" db:"user_agent" example:"Mozilla/5.0"`
	IP        string    `json:"ip" db:"ip" example:"192.168.1.1"`
	IssuedAt  time.Time `json:"issued_at" db:"issued_at"`
	Revoked   bool      `json:"revoked" db:"revoked"`
}

// TokenPair represents a pair of access and refresh tokens
// @Description Access and refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="`
}
