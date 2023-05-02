/*
 * wgvpn client - Copyright (C) 2023-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/davidcoles/oauth2"
)

const FACILITY = "oauth2"

type Oauth2 struct {
	ExpiryDelta  uint16   `json:"expirydelta"`
	Address      string   `json:"address"`
	ClientID     string   `json:"clientid"`
	ClientSecret string   `json:"clientsecret"`
	ProviderURL  string   `json:"providerurl"`
	Scopes       []string `json:"scopes"`
}

type Auth struct {
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
	Config   oauth2.Config
	roles    Roles
}

type source = Token

type Token struct {
	Token       oauth2.Token
	IDToken     string
	verifier    *oidc.IDTokenVerifier
	tokenSource oauth2.TokenSource
	roles       Roles
}

type Roles struct {
	Prefix string            `json:"prefix"`
	Claim  string            `json:"claim"`
	Force  string            `json:"force"`
	Match  []string          `json:"match"`
	Map    map[string]string `json:"map"`
}

func Init(o Oauth2, r Roles) (*Auth, error) {

	if o.ExpiryDelta > 0 {
		oauth2.ExpiryDelta = time.Duration(o.ExpiryDelta) * time.Minute
	}

	provider, err := oidc.NewProvider(context.TODO(), o.ProviderURL)

	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  "https://" + o.Address + "/callback",
		Endpoint:     Endpoint(provider), //Endpoint: provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID, "profile", "email"}, o.Scopes...),
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: o.ClientID})

	return &Auth{Provider: provider, Verifier: verifier, Config: oauth2Config, roles: r}, nil
}

func Endpoint(provider *oidc.Provider) oauth2.Endpoint {
	e := provider.Endpoint()
	return oauth2.Endpoint{AuthURL: e.AuthURL, TokenURL: e.TokenURL, AuthStyle: oauth2.AuthStyle(e.AuthStyle)}
}

func (f *Auth) AuthCodeURL(cn string) string {
	return f.Config.AuthCodeURL(cn, oauth2.AccessTypeOffline)
}

func (f *Auth) Exchange(code string) (*source, error) {
	oauth2Token, err := f.Config.Exchange(context.TODO(), code)

	if err != nil {
		return nil, err
	}

	if oauth2Token == nil {
		return nil, errors.New("oauth2Token is nil")
	}

	if !oauth2Token.Valid() {
		return nil, errors.New("oauth2Token is not valid")
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)

	if !ok {
		return nil, errors.New("no rawIDToken")
	}

	return &source{
		tokenSource: f.Config.TokenSource(context.TODO(), oauth2Token),
		Token:       *oauth2Token,
		IDToken:     rawIDToken,
		verifier:    f.Verifier,
		roles:       f.roles,
	}, nil
}

func (f *Auth) Unpickle(s string) *source {

	var source source

	b, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		return nil
	}

	err = json.Unmarshal(b, &source)

	if err != nil {
		return nil
	}

	extra := make(map[string]interface{})

	if source.IDToken != "" {
		extra["id_token"] = source.IDToken
	}

	source.Token = *(source.Token.WithExtra(extra))
	source.verifier = f.Verifier
	source.tokenSource = f.Config.TokenSource(context.TODO(), &(source.Token))
	source.roles = f.roles

	if !source.Validate() {
		return nil
	}

	return &source
}

func (s *source) Pickle() string {
	js, _ := json.Marshal(s)
	return base64.StdEncoding.EncodeToString(js)
}

func (s *source) Validate() bool {

	token, err := s.tokenSource.Token()

	if err != nil {
		return false
	}

	if token == nil {
		return false
	}

	if !valid(token) {
		return false
	}

	rawIDToken, ok := token.Extra("id_token").(string)

	if !ok {
		return false
	}

	_, err = s.verifier.Verify(context.TODO(), rawIDToken)

	if err != nil {
		return false
	}

	s.Token = *token
	s.IDToken = rawIDToken

	return true
}

func (t *Token) Username() string {
	c, err := t.Info()

	if err != nil {
		return ""
	}
	return c.Username
}

func (t *Token) Info() (Claims, error) {

	var c Claims

	idToken, err := t.verifier.Verify(context.TODO(), t.IDToken)

	if err != nil {
		return c, err
	}

	err = c.Parse(idToken)

	if err != nil {
		return c, err
	}

	return c, nil
}

func (t *Token) Refresh() bool {

	token, err := t.tokenSource.Token()

	if err != nil {
		return false
	}

	if !token.Valid() {
		return false
	}

	if t.Token.Expiry == token.Expiry {
		return false
	}

	rawIDToken, ok := token.Extra("id_token").(string)

	if !ok {
		return false
	}

	_, err = t.verifier.Verify(context.TODO(), rawIDToken)

	if err != nil {
		return false
	}

	t.Token = *token
	t.IDToken = rawIDToken

	return true
}

func (t *Token) Expiry() time.Time {
	return t.Token.Expiry
}

func (t *Token) Valid() bool {
	return valid(&(t.Token))
}

func valid(t *oauth2.Token) bool {
	return t != nil && t.AccessToken != "" && !expired(t)
}
func expired(t *oauth2.Token) bool {
	return t.Expiry.Round(0).Before(time.Now())
}

type Claims struct {
	Subject   string `json:"sub"`
	Email     string `json:"email"`
	Expiry    int    `json:"exp"`
	IssuedAt  int    `json:"iat"`
	Username  string `json:"preferred_username"`
	Name      string `json:"name"`
	GivenName string `json:"given_name"`
	Verified  bool   `json:"email_verified"`
	extra     map[string]interface{}
}

func (c *Claims) Parse(idToken *oidc.IDToken) error {
	err := idToken.Claims(c)

	if err != nil {
		return err
	}

	err = idToken.Claims(&(c.extra))

	if err != nil {
		return err
	}

	return nil
}

func (c *Claims) Claim(key string) []string {
	v, ok := c.extra[key]

	if !ok {
		return nil
	}

	s, ok := v.(string)

	if ok {
		return []string{s}
	}

	var ss []string

	ssi, ok := v.([]interface{})

	if !ok {
		return ss
	}

	for _, n := range ssi {
		y, ok := n.(string)
		if ok {
			ss = append(ss, y)
		}
	}

	return ss
}

func (t *Token) Roles() []string {

	idToken, err := t.verifier.Verify(context.TODO(), t.IDToken)

	if err != nil {
		return nil
	}

	var c Claims
	err = c.Parse(idToken)

	if err != nil {
		return nil
	}

	return t.roles.Roles(c)
}

func (r *Roles) Roles(c Claims) []string {

	roles := c.Claim(r.Claim)

	if len(r.Match) > 0 {

		m := map[string]bool{}

		for _, v := range roles {
			m[v] = true
		}

		roles = nil

		for _, v := range r.Match {
			if _, ok := m[v]; ok {
				roles = []string{v}
				break
			}
		}
	}

	if len(r.Map) > 0 {
		o := roles
		roles = nil

		for _, k := range o {
			if v, ok := r.Map[k]; ok {
				roles = append(roles, v)
			} else {
				roles = append(roles, k)
			}
		}
	}

	if r.Force != "" {
		roles = []string{r.Force}
	}

	for k, v := range roles {
		roles[k] = r.Prefix + v
	}

	return roles
}
