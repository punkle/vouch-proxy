/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
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
	return true
}
// GetUserInfo provider specific call to get userinfomation
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	_, _, err := common.PrepareTokensAndClient(r, ptokens, true)
	if err != nil {
		return err
	}

	// For Azure AD, there is very little information in the /userinfo response.
	// Since we can get everything we currently need from the access token, we are
	// just going to extract user info and custom claims from there.
	azureUser := structs.AzureUser{}

	tokenParts := strings.Split(ptokens.PAccessToken, ".")
	if len(tokenParts) < 2 {
		err = fmt.Errorf("azure GetUserInfo: invalid token received; not enough parts")
		log.Error(err)
		return err
	}

	accessTokenBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		err = fmt.Errorf("azure GetUserInfo: decoding token failed: %+v", err)
		log.Error(err)
		return err
	}

	if err = common.MapClaims(accessTokenBytes, customClaims); err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("azure GetUserInfo: getting user info from accessToken: %+v", string(accessTokenBytes))
	if err = json.Unmarshal(accessTokenBytes, &azureUser); err != nil {
		err = fmt.Errorf("azure getUserInfoFromTokens: unpacking token into AzureUser failed: %+v", err)
		log.Error(err)
		return err
	}

	azureUser.PrepareUserData()

	user.Username = azureUser.Username
	user.Name = azureUser.Name
	user.Email = azureUser.Email
	log.Infof("azure GetUserInfo: User: %+v", user)

	return nil
}
