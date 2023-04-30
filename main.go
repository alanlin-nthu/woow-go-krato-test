package main

import (
	"embed"
	"fmt"
	"net/http"

	"github.com/atreya2011/kratos-test/server"
	log "github.com/sirupsen/logrus"
)

/*
	Ory Hydra是一個OAuth2.0和OpenID Connect（OIDC）服務器，它提供了授權管理、令牌管理、用戶認證等功能，可以用於保護API和微服務的資源。
	Ory Kratos則是一個身份管理系統，它提供了用戶註冊、登錄、密碼重置等功能，可以用於管理用戶身份和權限。
	在實際應用中，Ory Hydra和Ory Kratos可以一起使用，以實現完整的身份驗證和授權系統。具體來說，可以通過以下步驟整合Ory Hydra和Ory Kratos：

	1. 在Ory Kratos中創建用戶並設置相關的身份和權限信息。
	2. 在API服務器中使用Ory Hydra進行授權管理，通過OIDC協議將Ory Hydra連接到Ory Kratos，以實現身份驗證。
	3. 當用戶訪問API時，Ory Hydra會使用OIDC協議向Ory Kratos驗證用戶身份，然後根據用戶的權限信息進行授權管理，以確保用戶只能訪問其有權訪問的資源。

	總的來說，Ory Hydra和Ory Kratos的整合可以提供一個安全、可擴展的身份驗證和授權系統，使得API和微服務能夠更加安全地運行。
*/

//go:embed templates
var templates embed.FS

//go:embed config/idp.yml
var idpConfYAML []byte

func main() {
	// create server
	/*
		// if use docker, change setting is
			kratosPublicEndpointAddress := "kratos:4433"
			hydraPublicEndpointAddress := "hydra:4444"
			hydraAdminEndpointAddress := "hydra:4445"
	*/
	kratosPublicEndpointAddress := "localhost:4433"
	hydraPublicEndpointAddress := "localhost:4444"
	hydraAdminEndpointAddress := "localhost:4445"

	s, err := server.NewServer(kratosPublicEndpointAddress,
		hydraPublicEndpointAddress,
		hydraAdminEndpointAddress,
		idpConfYAML,
		templates)
	if err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/login", s.HandleLogin)
	http.HandleFunc("/logout", s.HandleLogout)
	http.HandleFunc("/error", s.HandleError)
	http.HandleFunc("/registration", server.EnsureCookieFlowID(s.KratosPublicEndpoint, "registration", s.HandleRegister))
	http.HandleFunc("/verification", server.EnsureCookieFlowID(s.KratosPublicEndpoint, "verification", s.HandleVerification))
	http.HandleFunc("/registered", server.EnsureCookieReferer(s.HandleRegistered))
	http.HandleFunc("/dashboard", s.HandleDashboard)
	http.HandleFunc("/recovery", server.EnsureCookieFlowID(s.KratosPublicEndpoint, "recovery", s.HandleRecovery))
	http.HandleFunc("/settings", server.EnsureCookieFlowID(s.KratosPublicEndpoint, "settings", s.HandleSettings))
	http.HandleFunc("/", s.HandleIndex)

	http.HandleFunc("/auth/consent", s.HandleHydraConsent)

	// start server
	log.Println("Auth Server listening on port 4455")
	addr := fmt.Sprintf(":%s", s.Port)
	log.Fatalln(http.ListenAndServe(addr, http.DefaultServeMux))
}
