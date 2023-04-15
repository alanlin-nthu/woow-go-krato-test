package server

import (
	"net/http"

	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
)

var Store = sessions.NewCookieStore([]byte("secret-key"))
var AppSession *sessions.Session

func initSession(r *http.Request) *sessions.Session {
	log.Println("session before get", AppSession)

	if AppSession != nil {
		return AppSession
	}

	session, err := Store.Get(r, "idp")
	AppSession = session

	log.Println("session after get", session)
	if err != nil {
		panic(err)
	}
	return session
}

func setSessionValue(w http.ResponseWriter, r *http.Request, key string, value interface{}) {
	session := initSession(r)
	session.Values[key] = value
	log.Printf("set session with key %s and value %s\n", key, value)
	session.Save(r, w)
}

func getSessionValue(w http.ResponseWriter, r *http.Request, key string) interface{} {
	session := initSession(r)
	value := session.Values[key]
	log.Printf("valWithOutType: %s\n", value)
	return value
}

func deleteSessionValues(w http.ResponseWriter, r *http.Request) {
	session := initSession(r)
	session.Options.MaxAge = -1
	log.Print("deleted session")
	session.Save(r, w)
}
