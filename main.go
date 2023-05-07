package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/atreya2011/kratos-test/server"
	"github.com/gorilla/sessions"
	hydra "github.com/ory/hydra-client-go"
	log "github.com/sirupsen/logrus"
)

//go:embed templates
var templates embed.FS

//go:embed config/idp.yml
var idpConfYAML []byte

func main() {
	// create server
	s, err := server.NewServer(4433, 4444, 4445, idpConfYAML, templates)
	if err != nil {
		log.Fatalln(err)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	/**
		create an OAuth2 client using the following command:
			curl -X POST 'http://localhost:4445/clients' \
			-H 'Content-Type: application/json' \
			--data-raw '{
					"client_id": "auth-code-client",
					"client_name": "Test OAuth2 Client",
					"client_secret": "secret",
					"grant_types": ["authorization_code", "refresh_token"],
					"redirect_uris": ["http://localhost:4455/dashboard"],
					"response_types": ["code", "id_token"],
					"scope": "openid offline",
					"token_endpoint_auth_method": "client_secret_post",
					"metadata": {"registration": true}
			}'
		(or)
		run the compiled binary setting the "-withoauthclient" flag to true to
		automatically create an oauth2 client on startup (not recommended for production)
	**/
	// create an OAuth2 client if none exists

	withOAuthClient := flag.Bool("withoauthclient", false, "Creates an OAuth2 client on startup")
	flag.Parse()

	if *withOAuthClient {
		_, _, err = s.HydraAPIClient.AdminApi.GetOAuth2Client(ctx, s.IDPConfig.ClientID).Execute()

		if err != nil {
			_, _, err = s.HydraAPIClient.AdminApi.CreateOAuth2Client(ctx).
				OAuth2Client(hydra.OAuth2Client{
					ClientId:                pointer.ToString(s.IDPConfig.ClientID),
					ClientName:              pointer.ToString("Test OAuth2 Client"),
					ClientSecret:            pointer.ToString(s.IDPConfig.ClientSecret),
					GrantTypes:              []string{"authorization_code", "refresh_token"},
					RedirectUris:            []string{fmt.Sprintf("http://34.27.50.28%s/dashboard", s.Port)},
					ResponseTypes:           []string{"code", "id_token"},
					Scope:                   pointer.ToString("openid offline"),
					TokenEndpointAuthMethod: pointer.ToString("client_secret_post"),
					Metadata:                s.IDPConfig.ClientMetadata,
				}).Execute()
			if err != nil {
				log.Fatalln("unable to create OAuth2 client: ", err)
			}
			log.Info("Successfully created OAuth2 client!")
		}
	} else {
		log.Info("Skipping OAuth2 client creation...")
	}

	server.Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   216000, // = 1h,
		HttpOnly: true,   // no websocket or any protocol else
	}

	http.HandleFunc("/login", s.HandleLogin)
	http.HandleFunc("/logout", s.HandleLogout)
	http.HandleFunc("/error", s.HandleError)
	http.HandleFunc("/registration", s.EnsureCookieFlowID("registration", s.HandleRegister))
	http.HandleFunc("/verification", s.EnsureCookieFlowID("verification", s.HandleVerification))
	http.HandleFunc("/registered", server.EnsureCookieReferer(s.HandleRegistered))
	http.HandleFunc("/dashboard", s.HandleDashboard)
	http.HandleFunc("/recovery", s.EnsureCookieFlowID("recovery", s.HandleRecovery))
	http.HandleFunc("/settings", s.EnsureCookieFlowID("settings", s.HandleSettings))
	http.HandleFunc("/", s.HandleIndex)

	http.HandleFunc("/auth/consent", s.HandleHydraConsent)

	// start server
	log.Println("Auth Server listening on port 4455")
	log.Fatalln(http.ListenAndServe(s.Port, http.DefaultServeMux))
}
