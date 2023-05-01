package server

import (
	"crypto/rand"
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

const (
	Path     = "/"
	MaxAge   = 216000 // 1h
	HttpOnly = true   // no websocket or any protocol else
)

type Metadata struct {
	Registration bool `json:"registration"`
	Verification bool `json:"verification"`
}

type idpConfig struct {
	ClientID       string                 `yaml:"client_id"`
	ClientSecret   string                 `yaml:"client_secret"`
	ClientMetadata map[string]interface{} `yaml:"client_metadata"`
	Port           int                    `yaml:"port"`
}

// server contains server information
type server struct {
	KratosAPIClient      *kratos.APIClient
	KratosPublicEndpoint string
	HydraAPIClient       *hydra.APIClient
	Port                 string
	OAuth2Config         *oauth2.Config
	IDPConfig            *idpConfig
	SessionValueStore    *SessionsStore
}

func NewServer(kratosPublicEndpointAddress, hydraPublicEndpointAddress, hydraAdminEndpointAddress string, idpConfYAML []byte) (*server, error) {
	// create a new kratos client for self hosted server
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: fmt.Sprintf("http://%s", kratosPublicEndpointAddress)}}
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	conf.HTTPClient = &http.Client{Jar: cj}

	hydraConf := hydra.NewConfiguration()
	hydraConf.Servers = hydra.ServerConfigurations{{URL: fmt.Sprintf("http://%s", hydraAdminEndpointAddress)}}

	idpConf := idpConfig{}

	if err := yaml.Unmarshal(idpConfYAML, &idpConf); err != nil {
		return nil, err
	}

	oauth2Conf := &oauth2.Config{
		ClientID:     idpConf.ClientID,
		ClientSecret: idpConf.ClientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/dashboard", idpConf.Port),
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("http://%s/oauth2/auth", hydraPublicEndpointAddress), // access from browser
			TokenURL: fmt.Sprintf("http://%s/oauth2/token", hydraAdminEndpointAddress), // access from server
		},
		Scopes: []string{"openid", "offline"},
	}

	log.Println("OAuth2 Config: ", oauth2Conf)

	return &server{
		KratosAPIClient:      kratos.NewAPIClient(conf),
		KratosPublicEndpoint: fmt.Sprintf("http://%s", kratosPublicEndpointAddress),
		HydraAPIClient:       hydra.NewAPIClient(hydraConf),
		Port:                 fmt.Sprintf("%d", idpConf.Port),
		OAuth2Config:         oauth2Conf,
		IDPConfig:            &idpConf,
		SessionValueStore:    NewSessionsStore([]byte("secret-key"), Path, MaxAge, HttpOnly),
	}, nil
}

// handleLogin handles login request from hydra and kratos login flow
func (s *server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	/*
		首先，獲取來自 URL 查詢參數的登錄挑戰和流程 ID。
		如果 URL 查詢參數中沒有登錄挑戰或流程 ID，則創建 OAuth2 狀態並將其存儲在會話中，然後開始 OAuth2 授權代碼流程。
		如果 URL 查詢參數中只有登錄挑戰，而沒有流程 ID，則從 Hydra 中獲取登錄請求，並獲取客戶端詳細信息。
		如果會話不存在，則重定向到登錄頁面並傳遞登錄挑戰。否則，接受 Hydra 登錄請求，將身份驗證信息存儲在會話中並返回授權代碼。
	*/

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
		s.SessionValueStore.SetSessionValue(w, r, "oauth2State", state)

		// start oauth2 authorization code flow
		redirectTo := s.OAuth2Config.AuthCodeURL(state)
		log.Infof("redirect to hydra, url: %s", redirectTo)
		http.Redirect(w, r, redirectTo, http.StatusFound)
		// writeHttpCodeWithData(w, http.StatusFound, redirectTo)
		return
	}

	var metadata Metadata

	// get login request from hydra only if there is no flow id in the url query parameters
	if flowID == "" {
		loginRes, _, err := s.HydraAPIClient.AdminApi.GetLoginRequest(r.Context()).LoginChallenge(challenge).Execute()
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized OAuth Client"))
			return
		}
		log.Println("got client id: ", loginRes.Client.ClientId)
		// get client details from hydra
		clientRes, _, err := s.HydraAPIClient.AdminApi.GetOAuth2Client(r.Context(), *loginRes.Client.ClientId).Execute()
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
			return
		}

		log.Println("got client metadata: ", clientRes.Metadata)

		// convert map to json string
		md, err := json.Marshal(clientRes.Metadata)
		if err != nil {
			log.Error(err)
			writeError(w, http.StatusInternalServerError, errors.New("unable to marshal metadata"))
			return
		}

		// convert json string to struct
		if err = json.Unmarshal([]byte(md), &metadata); err != nil {
			log.Error(err)
			writeError(w, http.StatusInternalServerError, errors.New("internal Server Error"))
			return
		}
	}

	// store metadata value in session
	v := s.SessionValueStore.GetSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if ok {
		metadata.Registration = reg
	} else {
		s.SessionValueStore.SetSessionValue(w, r, "canRegister", metadata.Registration)
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
			// writeHttpCodeWithData(w, http.StatusFound, redirectTo)
			return
		}

		// get cookie from headers
		cookie := r.Header.Get("cookie")
		// get the login flow
		flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRecoveryFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		// templateData := templateData{
		// 	Title:     "Login",
		// 	UI:        &flow.Ui,
		// 	Metadata:  metadata,
		// 	Templates: s.templates,
		// }

		// // render template index.html
		// templateData.Render(w)
		writeHttp200(w, flow)
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
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
		return
	}

	// writeHttpCodeWithData(w, http.StatusFound, res.RedirectTo)
	http.Redirect(w, r, res.RedirectTo, http.StatusFound)
}

// handleLogout handles kratos logout flow
func (s *server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	/*
		1. 從 HTTP 請求中取得 cookie 以及 logout_challenge。
		2. 透過 Kratos API 創建 Self-Service Logout Flow，並回傳 Logout URL。
		3. 如果 Logout Flow 已存在，將使用者重新導向至 Logout URL。
		4. 如果 Logout Flow 不存在，則會從 Hydra API 取得 Logout Request，並進行驗證。
		5. 驗證成功後，將使用者重新導向至 Logout Request 中所指定的 redirect URL。
		6. 如果 Logout Flow 不存在且無法從 Hydra API 取得 Logout Request，則會將使用者重新導向至 /login，表示使用者未登入或登入已過期。
	*/
	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get logout challenge from url query parameters
	challenge := r.URL.Query().Get("logout_challenge")
	// create self-service logout flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.CreateSelfServiceLogoutFlowUrlForBrowsers(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		if challenge == "" {
			v := s.SessionValueStore.GetSessionValue(w, r, "idToken")
			idToken, ok := v.(string)
			if !ok {
				idToken = ""
			}
			http.Redirect(w, r, fmt.Sprintf("http://localhost:4444/oauth2/sessions/logout?id_token_hint=%s", idToken), http.StatusSeeOther)
			// writeHttpCodeWithData(w, http.StatusSeeOther, fmt.Sprintf("http://localhost:4444/oauth2/sessions/logout?id_token_hint=%s", idToken))
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
			s.SessionValueStore.DelSessionValue(w, r)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			// writeHttpCodeWithData(w, http.StatusSeeOther, redirectURL)
			return
		}
	}
	// redirect to logout url if session is valid
	if flow != nil {
		http.Redirect(w, r, flow.LogoutUrl, http.StatusFound)
		// writeHttpCodeWithData(w, http.StatusFound, flow.LogoutUrl)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	// writeHttpCodeWithData(w, http.StatusSeeOther, "/login")
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

	writeHttp200(w, errorDetails)
}

// handleRegister handles kratos registration flow
func (s *server) HandleRegister(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	/*
		該函數通過 cookie 和 flowID 從 Kratos API 中獲取註冊流程。然後，它檢查會話中的元數據值，以確定該用戶是否有權進行註冊。
		如果用戶有權進行註冊，該函數會使用模板引擎將註冊表單渲染為 HTML 並返回給瀏覽器顯示。如果用戶無權進行註冊，則返回 HTTP 狀態碼 401 Unauthorized。
	*/

	// get the registration flow
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRegistrationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// check metadata value in session
	v := s.SessionValueStore.GetSessionValue(w, r, "canRegister")
	reg, ok := v.(bool)
	if !ok || !reg {
		writeError(w, http.StatusUnauthorized, errors.New("Unauthorized"))
		return
	}

	// templateData := templateData{
	// 	Title:     "Registration",
	// 	UI:        &flow.Ui,
	// 	Templates: s.templates,
	// }
	// // render template index.html
	// templateData.Render(w)

	writeHttp200(w, flow)
}

// handleVerification handles kratos verification flow
func (s *server) HandleVerification(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	/*
		這個函數接收三個參數：一個 http.ResponseWriter 類型的變數，一個 http.Request 類型的變數，以及兩個字符串變數 cookie 和 flowID。

		1. 函數從 Kratos API 中獲取自助驗證流程的相關信息，其中包括驗證頁面的 UI 設計和流程 ID。
		2. 如果獲取流程信息時出現錯誤，則函數將使用 http.StatusUnauthorized 狀態碼返回錯誤信息並退出。否則，函數將使用自助驗證流程信息渲染模板，包括標題、UI 設計和模板。
		3. 如果驗證成功，標題將更新為 "Verification Complete"，並且 UI 設計將被設置為 nil。
		4. 最後，函數將渲染模板並將其作為 HTTP 響應返回給用戶。
	*/

	// get self-service verification flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceVerificationFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// title := "Verify your Email address"
	ui := &flow.Ui
	if flow.Ui.Messages != nil {
		for _, message := range flow.Ui.Messages {
			if strings.ToLower(message.GetText()) == "you successfully verified your email address." {
				// title = "Verification Complete"
				ui = nil
			}
		}
	}
	// templateData := templateData{
	// 	Title:     title,
	// 	UI:        ui,
	// 	Templates: s.templates,
	// }
	// // render template index.html
	// templateData.Render(w)
	writeHttp200(w, ui)
}

// handleRegistered displays registration complete message to user
func (s *server) HandleRegistered(w http.ResponseWriter, r *http.Request) {
	/*
		函數 HandleRegistered，當用戶完成註冊時會被調用，並將用戶重定向到註冊完成的頁面。在這個函數中，
		我們創建一個模板數據結構，包括網頁標題和模板，然後使用這個結構渲染模板 index.html，並將渲染結果作為 HTTP 響應返回給用戶。
	*/

	writeHttp200(w, "Registration Complete")
}

// handleRecovery handles kratos recovery flow
func (s *server) HandleRecovery(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	/*
		函數 HandleRecovery，處理了使用者忘記密碼的情況。如果使用者發送了一個重設密碼的請求，
		該函式將從Kratos API獲取恢復流程，並將其傳遞給模板引擎進行渲染。這個函式需要三個參數，分別是 w，r 和 cookie 和 flowID。
		如果獲取流程的過程中發生了錯誤，函式將回傳錯誤訊息和狀態碼。最後，該函式使用模板引擎呈現恢復流程的用戶介面，
		以便使用者可以輸入他們的電子郵件和驗證碼。
	*/

	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceRecoveryFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// templateData := templateData{
	// 	Title:     "Password Recovery Form",
	// 	UI:        &flow.Ui,
	// 	Templates: s.templates,
	// }
	// // render template index.html
	// templateData.Render(w)

	// jsonData, err := json.Marshal(flow)
	// if err != nil {
	// 	writeError(w, http.StatusInternalServerError, err)
	// 	return
	// }
	writeHttp200(w, flow)

}

// handleSettings handles kratos settings flow
func (s *server) HandleSettings(w http.ResponseWriter, r *http.Request, cookie, flowID string) {
	/*
		用於處理身份驗證和帳戶管理相關的 HTTP 請求。其中的 HandleSettings 函數會從 Kratos 的 API 中取得使用者的設置流程，
		並在網頁上顯示相關的 UI 元素。這個函數會接收一個 http.ResponseWriter 和一個 http.Request 物件，以及兩個字串參數 cookie 和 flowID。
		其中，cookie 是用於驗證使用者身份的 cookie，而 flowID 則是設置流程的 ID，用於從 Kratos 的 API 中取得相關的資料。
		如果函數成功取得了設置流程的資料，則會在網頁上顯示相應的 UI 元素，否則會回傳一個錯誤頁面。
		最後，這個函數會呼叫 templateData.Render 方法，將相關的 HTML 模板和資料傳遞給 http.ResponseWriter，並渲染出最終的網頁內容。
	*/

	// get self-service recovery flow for browser
	flow, _, err := s.KratosAPIClient.V0alpha2Api.GetSelfServiceSettingsFlow(r.Context()).Id(flowID).Cookie(cookie).Execute()
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// templateData := templateData{
	// 	Title:     "Settings",
	// 	UI:        &flow.Ui,
	// 	Templates: s.templates,
	// }
	// // render template index.html
	// templateData.Render(w)
	writeHttp200(w, flow)
}

// handleDashboard shows dashboard
func (s *server) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	/*
		用於處理用戶控制台的請求。它首先檢查用戶是否已經通過驗證，如果沒有，則重定向到登錄頁面。
		接著，它將獲取來自 URL 查詢參數的 OAuth2 狀態和授權碼，然後使用授權碼交換訪問令牌。
		最後，它將 ID Token 存儲在會話中並將會話詳細信息渲染到模板中返回給用戶。
	*/

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		// writeHttpCodeWithData(w, http.StatusFound, "/login")
		return
	}

	// // marshal session to json
	// sessionJSON, err := json.MarshalIndent(session, "", "  ")
	// if err != nil {
	// 	writeError(w, http.StatusInternalServerError, err)
	// 	return
	// }

	// get oauth2 state from session
	v := s.SessionValueStore.GetSessionValue(w, r, "oauth2State")
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
	s.SessionValueStore.SetSessionValue(w, r, "idToken", idt)

	// templateData := templateData{
	// 	Title:     "Session Details",
	// 	Details:   string(sessionJSON),
	// 	Templates: s.templates,
	// }
	// // render template index.html
	// templateData.Render(w)

	writeHttp200(w, session)
}

// handleHydraConsent shows hydra consent screen
func (s *server) HandleHydraConsent(w http.ResponseWriter, r *http.Request) {
	/*
		此函式為處理 Hydra 認可請求的 HTTP 請求處理函式。函式流程如下：

		1. 從 HTTP 請求的 URL 查詢參數中取得認可請求的 challenge 值。
		2. 如果 challenge 為空，則返回未經授權的 OAuth 用戶端錯誤。
		3. 使用 Hydra 的管理 API，通過 challenge 值獲取相應的 consent request。
		4. 從 HTTP 請求標頭中取得 cookie，使用該 cookie 獲取用戶會話詳細信息。
		5. 接受同意請求，並在用戶會話的 id_token 中添加可驗證地址。
		6. 如果有任何錯誤發生，返回未經授權的 OAuth 用戶端錯誤。
		7. 重定向到同意請求的 redirect URL。

		因此，此函式的作用是在 Hydra 的認可請求流程中處理同意請求。
	*/

	// get consent challenge from url query parameters
	challenge := r.URL.Query().Get("consent_challenge")

	if challenge == "" {
		log.Println("Missing consent challenge")
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
		return
	}

	// get consent request
	getConsentRes, _, err := s.HydraAPIClient.AdminApi.GetConsentRequest(r.Context()).ConsentChallenge(challenge).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
		return
	}

	// get cookie from headers
	cookie := r.Header.Get("cookie")
	// get session details
	session, _, err := s.KratosAPIClient.V0alpha2Api.ToSession(r.Context()).Cookie(cookie).Execute()
	if err != nil {
		log.Error(err)
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
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
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized OAuth Client"))
		return
	}

	http.Redirect(w, r, acceptConsentRes.RedirectTo, http.StatusFound)
	// writeHttpCodeWithData(w, http.StatusFound, acceptConsentRes.RedirectTo)
}

func (s *server) HandleIndex(w http.ResponseWriter, r *http.Request) {
	b, _ := httputil.DumpRequest(r, true)
	log.Println(string(b))
	// w.WriteHeader(200)
	writeHttp200(w, "")
}
