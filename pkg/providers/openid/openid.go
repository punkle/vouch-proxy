/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package openid

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"fmt"
	"bytes"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"go.uber.org/zap"
)

// Provider provider specific functions
type Provider struct{}

var log *zap.SugaredLogger

// Configure see main.go configure()
func (Provider) Configure() {
	log = cfg.Logging.Logger
}

func (Provider) Validate(r *http.Request, jwt string) bool {
	claims, _ := jwtmanager.ClaimsFromJWT(jwt)
	var jsonStr = []byte(fmt.Sprintf(`token=%s`, claims.PAccessToken))
	req, _ := http.NewRequest("POST", cfg.GenOAuth.IntrospectURL, bytes.NewBuffer(jsonStr))
	req.SetBasicAuth(cfg.OAuthClient.ClientID, cfg.OAuthClient.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
			return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Info("failed oidc access_token validation")
		return false
	} else {
		log.Info("suceeded oidc access_token validation")
		return true
	}
}

// GetUserInfo provider specific call to get userinfomation
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	client, _, err := common.PrepareTokensAndClient(r, ptokens, true)
	if err != nil {
		return err
	}

	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("OpenID userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	if err = json.Unmarshal(data, user); err != nil {
		log.Error(err)
		return err
	}
	user.PrepareUserData()
	return nil
}
