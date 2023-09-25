package cf_token_generator

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/segmentio/ksuid"
	"log"
	"net/url"
	"time"
)

type CustomToken struct {
	Secrets map[string]string
	Method  jwt.SigningMethod
}

type TokenPolicy struct {
	Country           bool
	Region            bool
	Session           bool
	Expiry            time.Duration
	FirstAccessExpiry time.Duration
	Headers           []string
	QueryStrings      []string
}

func DefaultTokenPolicy() *TokenPolicy {
	return &TokenPolicy{
		Country:      false,
		Region:       false,
		Session:      true,
		Headers:      []string{"user-agent", "referer"},
		QueryStrings: []string{},
	}
}

type ViewerAttributes struct {
	Country      string
	Region       string
	SessionId    string
	Headers      map[string]string
	QueryStrings map[string]string
}

func NewCustomToken(secrets map[string]string) *CustomToken {
	return &CustomToken{Secrets: secrets, Method: jwt.SigningMethodHS256}
}

func NewCustomTokenSingleSecret(keyId string, key string) *CustomToken {
	return NewCustomToken(map[string]string{keyId: key})
}

func (t *CustomToken) GenerateUrlFromViewerAttributes(endpointUrl url.URL, keyId string, tokenPolicy *TokenPolicy, viewerAttrs *ViewerAttributes) (string, error) {
	claims := jwt.MapClaims{
		"co":      false,
		"reg":     false,
		"ssn":     false,
		"headers": []string{},
		"qs":      []string{},
		"exp":     time.Now().Add(tokenPolicy.Expiry).Unix(),
		"faExp":   time.Now().Add(tokenPolicy.FirstAccessExpiry).Unix(),
	}
	intsigInput := ""
	if tokenPolicy.Country {
		claims["co"] = true
		intsigInput = fmt.Sprintf("%s%s:", intsigInput, viewerAttrs.Country)
	}
	if tokenPolicy.Region {
		claims["reg"] = true
		intsigInput = fmt.Sprintf("%s%s:", intsigInput, viewerAttrs.Region)
	}
	sessionId := ""
	if tokenPolicy.Session {
		claims["ssn"] = true
		sessionId = viewerAttrs.SessionId
		if sessionId == "" {
			sessionId = ksuid.New().String()
		}
		intsigInput = fmt.Sprintf("%s%s:", intsigInput, sessionId)
	}
	if len(tokenPolicy.Headers) > 0 {
		var payloadHeaders []string
		for i := range tokenPolicy.Headers {
			header := tokenPolicy.Headers[i]
			payloadHeaders = append(payloadHeaders, header)
			if val, ok := viewerAttrs.Headers[header]; ok {
				intsigInput = fmt.Sprintf("%s%s:", intsigInput, val)
			}
		}
		claims["headers"] = payloadHeaders
	}

	if len(tokenPolicy.QueryStrings) > 0 {
		var payloadQs []string
		for i := range tokenPolicy.QueryStrings {
			qs := tokenPolicy.QueryStrings[i]
			payloadQs = append(payloadQs, qs)
			if val, ok := viewerAttrs.QueryStrings[qs]; ok {
				intsigInput = fmt.Sprintf("%s%s:", intsigInput, val)
			}
		}
		claims["qs"] = payloadQs
	}
	if intsigInput != "" {
		intsigInput = intsigInput[0 : len(intsigInput)-1]
		log.Println(fmt.Sprintf("[%s]", intsigInput))
		intSignSign, err := t.Method.Sign(intsigInput, []byte(t.Secrets[keyId]))
		if err != nil {
			return intsigInput, err
		}
		claims["intsig"] = intSignSign
	}
	token, err := t.GenerateTokenWithClaims(keyId, claims)
	if err != nil {
		return "", err
	}
	if len(sessionId) > 0 {
		return fmt.Sprintf("%s://%s/%s.%s%s", endpointUrl.Scheme, endpointUrl.Host, sessionId, token, endpointUrl.Path), nil
	}
	return fmt.Sprintf("%s://%s/%s%s", endpointUrl.Scheme, endpointUrl.Host, token, endpointUrl.Path), nil
}

func (t *CustomToken) GenerateUrlWithClaims(endpointUrl url.URL, keyId string, claims jwt.MapClaims) (string, error) {
	token, err := t.GenerateTokenWithClaims(keyId, claims)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s/%s%s", endpointUrl.Scheme, endpointUrl.Host, token, endpointUrl.Path), nil
}

func (t *CustomToken) GenerateTokenWithClaims(keyId string, claims jwt.MapClaims) (string, error) {
	jwtObj := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": t.Method.Alg(),
			"kid": keyId,
		},
		Claims: claims,
		Method: t.Method,
	}
	return jwtObj.SignedString([]byte(t.Secrets[keyId]))
}

func (t *CustomToken) GenerateUrl(endpointUrl url.URL, keyId string, exp time.Duration) (string, error) {
	return t.GenerateUrlWithClaims(endpointUrl, keyId, jwt.MapClaims{
		"exp": time.Now().Add(exp).Unix(),
	})
}
