package server

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

type SessionsStore struct {
	secretKey   []byte
	store       *sessions.CookieStore
	idpSessions *sessions.Session
}

func NewSessionsStore(_secretKey []byte, path string, maxAge int, httpOnly bool) *SessionsStore {

	storeTmp := sessions.NewCookieStore([]byte(_secretKey))
	storeTmp.Options = &sessions.Options{
		Path:     path,
		MaxAge:   maxAge,   // = 1h,
		HttpOnly: httpOnly, // no websocket or any protocol else
	}

	return &SessionsStore{
		secretKey:   _secretKey,
		store:       storeTmp,
		idpSessions: nil,
	}
}

func (p *SessionsStore) SecretKey() []byte {
	return p.secretKey
}

func (p *SessionsStore) Store() *sessions.CookieStore {
	return p.store
}

// func (p *SessionsStore) IdpSessions() *sessions.Session {
// 	return p.idpSessions
// }

// inside func
// get session from store of github.com/gorilla/sessions
func (p *SessionsStore) getSessionFromStore(r *http.Request) *sessions.Session {
	if p.idpSessions != nil {
		return p.idpSessions
	}

	session, err := p.store.Get(r, "idp")
	if err != nil {
		return nil
	} else {
		p.idpSessions = session
		return session
	}
}

func (p *SessionsStore) SetSessionValue(w http.ResponseWriter, r *http.Request, key string, value interface{}) {
	session := p.getSessionFromStore(r)
	if session != nil {
		session.Values[key] = value
	} else {
		log.Printf("get session faild,requesty: %v, key: %v, value: %v", r, key, value)
	}
}

//
func (p *SessionsStore) GetSessionValue(w http.ResponseWriter, r *http.Request, key string) interface{} {
	session := p.getSessionFromStore(r)
	if session != nil {
		return session.Values[key]
	} else {
		return nil
	}
}

//
func (p *SessionsStore) DelSessionValue(w http.ResponseWriter, r *http.Request) {
	session := p.getSessionFromStore(r)
	if session != nil {
		session.Options.MaxAge = -1
		_ = session.Save(r, w)
	}
}
