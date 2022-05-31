package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"golang.org/x/oauth2"
)

var (
	SigningKey        []byte
	EncryptionKey     []byte
	UserSigningKey    []byte
	UserEncryptionKey []byte
	OIDCProvider      *oidc.Provider
	Oauth2Config      oauth2.Config
)

var ExpiryTime time.Duration = 5

type customClaims struct {
	RemoteServer string `json:"remoteServer"`
	ClientIP     string `json:"clientIp"`
	AccessToken  string `json:"accessToken"`
}

func UserInfo(ctx context.Context, token string) (jwt.Claims, error) {
	standard := jwt.Claims{}
	if len(UserEncryptionKey) > 0 && len(UserSigningKey) > 0 {
		enc, err := jwt.ParseSignedAndEncrypted(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		token, err := enc.Decrypt(UserEncryptionKey)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
		if _, err := verifyAlg(token.Headers, string(jose.HS256)); err != nil {
			log.Printf("signature validation failure: %s", err)
			return standard, errors.New("signature validation failure")
		}
		if err = token.Claims(UserSigningKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return standard, errors.New("cannot verify signature")
		}
	} else if len(UserSigningKey) == 0 {
		token, err := jwt.ParseEncrypted(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		err = token.Claims(UserEncryptionKey, &standard)
		if err != nil {
			log.Printf("Cannot decrypt token %s", err)
			return standard, errors.New("cannot decrypt token")
		}
	} else {
		token, err := jwt.ParseSigned(token)
		if err != nil {
			log.Printf("Cannot get token %s", err)
			return standard, errors.New("cannot get token")
		}
		if _, err := verifyAlg(token.Headers, string(jose.HS256)); err != nil {
			log.Printf("signature validation failure: %s", err)
			return standard, errors.New("signature validation failure")
		}
		err = token.Claims(UserSigningKey, &standard)
		if err = token.Claims(UserSigningKey, &standard); err != nil {
			log.Printf("cannot verify signature %s", err)
			return standard, errors.New("cannot verify signature")
		}
	}

	// go-jose doesnt verify the expiry
	err := standard.Validate(jwt.Expected{
		Issuer: "rdpgw",
		Time:   time.Now(),
	})

	if err != nil {
		log.Printf("token validation failed due to %s", err)
		return standard, fmt.Errorf("token validation failed due to %s", err)
	}

	return standard, nil
}

func getSessionInfo(ctx context.Context) *protocol.SessionInfo {
	s, ok := ctx.Value("SessionInfo").(*protocol.SessionInfo)
	if !ok {
		log.Printf("cannot get session info from context")
		return nil
	}
	return s
}

func verifyAlg(headers []jose.Header, alg string) (bool, error) {
	for _, header := range headers {
		if header.Algorithm != alg {
			return false, fmt.Errorf("invalid signing method %s", header.Algorithm)
		}
	}
	return true, nil
}
