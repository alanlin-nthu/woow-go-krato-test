package server

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/atreya2011/kratos-test/generated/go/service"
	hydra "github.com/ory/hydra-client-go"
	kratos "github.com/ory/kratos-client-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type idpConfig struct {
	ClientID       string                 `yaml:"client_id"`
	ClientSecret   string                 `yaml:"client_secret"`
	ClientMetadata map[string]interface{} `yaml:"client_metadata"`
	Port           int                    `yaml:"port"`
}

// writeError writes error to the response
func writeError(w http.ResponseWriter, statusCode int, err error) {
	w.WriteHeader(statusCode)
	if _, e := w.Write([]byte(err.Error())); e != nil {
		log.Fatal(err)
	}
}

// server contains server information
type server struct {
	KratosAPIClient      *kratos.APIClient
	KratosPublicEndpoint string
	HydraAPIClient       *hydra.APIClient
	Port                 string
	OAuth2Config         *oauth2.Config
	IDPConfig            *idpConfig
	templates            embed.FS
}

func NewServer(kratosPublicEndpointPort, hydraPublicEndpointPort, hydraAdminEndpointPort int, idpConfYAML []byte, templates embed.FS) (*server, error) {
	// create a new kratos client for self hosted server
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: fmt.Sprintf("http://kratos:%d", kratosPublicEndpointPort)}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}

	hydraConf := hydra.NewConfiguration()
	hydraConf.Servers = hydra.ServerConfigurations{{URL: fmt.Sprintf("http://hydra:%d", hydraAdminEndpointPort)}}

	idpConf := idpConfig{}

	if err := yaml.Unmarshal(idpConfYAML, &idpConf); err != nil {
		return nil, err
	}

	oauth2Conf := &oauth2.Config{
		ClientID:     idpConf.ClientID,
		ClientSecret: idpConf.ClientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/dashboard", idpConf.Port),
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://localhost:%d/oauth2/auth", hydraPublicEndpointPort), // access from browser
			TokenURL: fmt.Sprintf("http://hydra:%d/oauth2/token", hydraPublicEndpointPort),    // access from server
		},
		Scopes: []string{"openid", "offline"},
	}

	log.Println("OAuth2 Config: ", oauth2Conf)

	return &server{
		KratosAPIClient:      kratos.NewAPIClient(conf),
		KratosPublicEndpoint: fmt.Sprintf("http://localhost:%d", kratosPublicEndpointPort),
		HydraAPIClient:       hydra.NewAPIClient(hydraConf),
		Port:                 fmt.Sprintf(":%d", idpConf.Port),
		OAuth2Config:         oauth2Conf,
		IDPConfig:            &idpConf,
		templates:            templates,
	}, nil
}

// handleLogin handles login request from hydra and kratos login flow
func (s *server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	// get login challenge from url query parameters
	challenge := r.URL.Query().Get("login_challenge")
	flowID := r.URL.Query().Get("flow")
	// redirect to login page if there is no login challenge or flow id in url query parameters
	if challenge == "" && flowID == "" {
		log.Println("No login challenge found or flow ID found in URL Query Parameters")

		// create oauth2 state and store in session
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			log.Error("generate state failed: %v", err)
			return
		}
		state := base64.StdEncoding.EncodeToString(b)
		setSessionValue(w, r, "oauth2State", state)

		// start oauth2 authorization code flow
		redirectTo := s.OAuth2Config.AuthCodeURL(state)
		log.Infof("redirect to hydra, url: %s", redirectTo)
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	var metadata Metadata

	// get login request from hydra only if there is no flow id in the url query parameters
	if flowID == "" {
		loginRes, _, err := s.HydraAPIClient.AdminApi.GetLoginRequest(r.Context()).LoginChallenge(challenge).Execute()
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}
		log.Println("got client id: ", loginRes.Client.ClientId)
		// get client details from hydra
		clientRes, _, err := s.HydraAPIClient.AdminApi.GetOAuth2Client(r.Context(), *loginRes.Client.ClientId).Execute()
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
			return
		}

		log.Println("got client metadata: ", clientRes.Metadata)

		// convert map to json string
		md, err := json.Marshal(clientRes.Metadata)
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusInternalServerError, errors.New("Unable to marshal metadata"))
			return
		}

		// convert json string to struct
		if err = json.Unmarshal([]byte(md), &metadata); err != nil {
			log.Error(err)
			writeError(w, http.StatusInternalServerError, errors.New("Internal Server Error"))
			return
		}
	}

	// store metadata value in session
	v := getSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if ok {
		metadata.Registration = reg
	} else {
		setSessionValue(w, r, "canRegister", metadata.Registration)
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")

	// check for kratos session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()

	// if there is no session, redirect to login page with login challenge
	if err != nil {
		// build return_to url with hydra login challenge as url query parameter
		returnToParams := url.Values{
			"login_challenge": []string{challenge},
		}
		returnTo := "/login?" + returnToParams.Encode()
		// build redirect url with return_to as url query parameter
		// refresh=true forces a new login from kratos regardless of browser sessions
		// this is important because we are letting Hydra handle sessions
		redirectToParam := url.Values{
			"return_to": []string{returnTo},
			"refresh":   []string{"true"},
		}
		redirectTo := fmt.Sprintf("%s/self-service/login/browser?", s.KratosPublicEndpoint) + redirectToParam.Encode()

		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")

		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// get the login flow
		flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceLoginFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		templateData := templateData{
			Title:     "Login",
			UI:        &flow.Ui,
			Metadata:  metadata,
			Templates: s.templates,
		}

		// render template index.html
		templateData.Render(w)
		return
	}

	// if there is a valid session, marshal session.identity.traits to json to be stored in subject
	traitsJSON, err := json.Marshal(session.Identity.Traits)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	subject := string(traitsJSON)

	// accept hydra login request
	res, _, err := s.HydraAPIClient.AdminApi.AcceptLoginRequest(r.Context()).
		LoginChallenge(challenge).
		AcceptLoginRequest(hydra.AcceptLoginRequest{
			Remember:    pointer.ToBool(true),
			RememberFor: pointer.ToInt64(3600),
			Subject:     subject,
		}).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	http.Redirect(w, r, res.RedirectTo, http.StatusFound)
}

// handleLogout handles kratos logout flow
func (s *server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get logout challenge from url query parameters
	challenge := r.URL.Query().Get("logout_challenge")
	// create self-service logout flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.CreateSelfServiceLogoutFlowUrlForBrowsers(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		if challenge == "" {
			v := getSessionValue(w, r, "idToken")
			idToken, ok := v.(string)
			if !ok {
				idToken = ""
			}
			http.Redirect(w, r, fmt.Sprintf("http://localhost:4444/oauth2/sessions/logout?id_token_hint=%s", idToken), http.StatusSeeOther)
			return
		} else {
			getLogoutRequestRes, _, err := s.HydraAPIClient.AdminApi.GetLogoutRequest(r.Context()).
				LogoutChallenge(challenge).Execute()
			log.Println(err)
			writeError(w, http.StatusUnauthorized, err)
			acceptLogoutRequestRes, _, err := s.HydraAPIClient.AdminApi.AcceptLogoutRequest(r.Context()).
				LogoutChallenge(challenge).Execute()
			if err != nil {
				log.Println(err)
				writeError(w, http.StatusUnauthorized, err)
			}
			redirectURL := acceptLogoutRequestRes.RedirectTo
			if getLogoutRequestRes.Client != nil {
				redirectURL = getLogoutRequestRes.Client.PostLogoutRedirectUris[0]
			}
			log.Println("logout redirect", redirectURL)
			deleteSessionValues(w, r)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}
	}
	// redirect to logout url if session is valid
	if flow != nil {
		http.Redirect(w, r, flow.LogoutUrl, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleError handles login/registration error
func (s *server) HandleError(w http.ResponseWriter, r *http.Request) {
	// get url query parameters
	errorID := r.URL.Query().Get("id")
	// get error details
	errorDetails, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceError(r.Context()).Id(errorID).Execute()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// marshal errorDetails to json
	errorDetailsJSON, err := json.MarshalIndent(errorDetails, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	templateData := templateData{
		Title:     "Error",
		Details:   string(errorDetailsJSON),
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleRegister handles kratos registration flow
func (s *server) HandleRegister(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get the registration flow
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRegistrationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// check metadata value in session
	v := getSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if !ok || !reg {
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	templateData := templateData{
		Title:     "Registration",
		UI:        &flow.Ui,
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleVerification handles kratos verification flow
func (s *server) HandleVerification(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service verification flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceVerificationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	title := "Verify your Email address"
	ui := &flow.Ui
	if flow.Ui.Messages != nil {
		for _, message := range flow.Ui.Messages {
			if strings.ToLower(message.GetText()) == "you successfully verified your email address." {
				title = "Verification Complete"
				ui = nil
			}
		}
	}
	templateData := templateData{
		Title:     title,
		UI:        ui,
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleRegistered displays registration complete message to user
func (s *server) HandleRegistered(w http.ResponseWriter, r *http.Request) {
	templateData := templateData{
		Title:     "Registration Complete",
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleRecovery handles kratos recovery flow
func (s *server) HandleRecovery(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRecoveryFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title:     "Password Recovery Form",
		UI:        &flow.Ui,
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleSettings handles kratos settings flow
func (s *server) HandleSettings(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceSettingsFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	templateData := templateData{
		Title:     "Settings",
		UI:        &flow.Ui,
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleDashboard shows dashboard
func (s *server) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// marshal session to json
	sessionJSON, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// get oauth2 state from session
	v := getSessionValue(w, r, "oauth2State")
	state, ok := v.(string)
	if !ok || state == "" {
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	// compare oauth2 state with state from url query
	if r.URL.Query().Get("state") != string(state) {
		log.Printf("states do not match, expected %s, got %s\n", string(state), r.URL.Query().Get("state"))
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	// get authorization code from url query and exchange it for access token
	code := r.URL.Query().Get("code")
	token, err := s.OAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("unable to exchange code for token: %s\n", err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	idt := token.Extra("id_token")
	log.Printf("Access Token:\n\t%s\n", token.AccessToken)
	log.Printf("Refresh Token:\n\t%s\n", token.RefreshToken)
	log.Printf("Expires in:\n\t%s\n", token.Expiry.Format(time.RFC1123))
	log.Printf("ID Token:\n\t%v\n\n", idt)

	// store idToken value in session
	setSessionValue(w, r, "idToken", idt)

	templateData := templateData{
		Title:     "Session Details",
		Details:   string(sessionJSON),
		Templates: s.templates,
	}
	// render template index.html
	templateData.Render(w)
}

// handleHydraConsent shows hydra consent screen
func (s *server) HandleHydraConsent(w http.ResponseWriter, r *http.Request) {
	// get consent challenge from url query parameters
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		log.Println("Missing consent challenge")
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// get consent request
	getConsentRes, _, err := s.HydraAPIClient.AdminApi.GetConsentRequest(r.Context()).ConsentChallenge(challenge).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	// accept consent request and add verifiable address to id_token in session
	acceptConsentRes, _, err := s.HydraAPIClient.AdminApi.AcceptConsentRequest(r.Context()).
		ConsentChallenge(challenge).
		AcceptConsentRequest(hydra.AcceptConsentRequest{
			GrantScope:  getConsentRes.RequestedScope,
			Remember:    pointer.ToBool(true),
			RememberFor: pointer.ToInt64(3600),
			Session: &hydra.ConsentRequestSession{
				IdToken: service.PersonSchemaJsonTraits{Email: session.Identity.VerifiableAddresses[0].Value},
			},
		}).Execute()

	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized OAuth Client"))
		return
	}

	http.Redirect(w, r, acceptConsentRes.RedirectTo, http.StatusFound)
}

// ensureCookieFlowID is a middleware function that ensures that a request contains
// flow ID in url query parameters and cookie in header
func (s *server) EnsureCookieFlowID(flowType string, next func(w http.ResponseWriter, r *http.Request, cookie, flowID string)) http.HandlerFunc {
	// create redirect url based on flow type
	redirectURL := fmt.Sprintf("%s/self-service/%s/browser", s.KratosPublicEndpoint, flowType)

	return func(w http.ResponseWriter, r *http.Request) {
		// get flowID from url query parameters
		flowID := r.URL.Query().Get("flow")
		// if there is no flow id in url query parameters, create a new flow
		if flowID == "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// if there is no cookie in header, return error
		if cookie == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing cookie"))
			return
		}

		// call next handler
		next(w, r, cookie, flowID)
	}
}

func (s *server) HandleIndex(w http.ResponseWriter, r *http.Request) {
	b, _ := httputil.DumpRequest(r, true)
	log.Println(string(b))
	w.WriteHeader(200)
}
