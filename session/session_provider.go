package session

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gofly/saml"
	"github.com/vanackere/ldap"
)

var (
	ErrBindFailed      = errors.New("ldap: bind failed")
	ErrSessionNotFound = errors.New("session is not found")
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	saml.RandReader.Read(rv)
	return rv
}

type LDAPSessProvider struct {
	ldapAddr      string
	bindDN        string
	sessionMaxAge time.Duration
	sessions      map[string]*saml.Session
}

func NewLDAPSessionProvider(ldapAddr, bindDN string, sessionMaxAge time.Duration) *LDAPSessProvider {
	return &LDAPSessProvider{
		ldapAddr:      ldapAddr,
		bindDN:        bindDN,
		sessionMaxAge: sessionMaxAge,
		sessions:      make(map[string]*saml.Session),
	}
}

func (p *LDAPSessProvider) GetSessionByUsernameAndPassword(username, password string) (*saml.Session, error) {
	ldapConn, err := ldap.DialTLS("tcp", p.ldapAddr, nil)
	if err != nil {
		log.Printf("ldap.DialTLS %s with error: %s \n", p.ldapAddr, err)
		return nil, err
	}
	defer ldapConn.Close()

	err = ldapConn.Bind(fmt.Sprintf("cn=%s,%s", username, p.bindDN), password)
	if err != nil {
		log.Printf("ldapConn.Bind(%s) with error: %s\n", username, err)
		return nil, ErrBindFailed
	}
	sessID := base64.StdEncoding.EncodeToString(randomBytes(32))
	return &saml.Session{
		ID:         sessID,
		NameID:     username,
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(p.sessionMaxAge),
		Index:      hex.EncodeToString(randomBytes(32)),
		UserName:   username,
	}, nil
}

func (p *LDAPSessProvider) GetSessionBySessionID(sessID string) (*saml.Session, error) {
	if session, ok := p.sessions[sessID]; ok {
		return session, nil
	}
	return nil, ErrSessionNotFound
}

func (p *LDAPSessProvider) SetSession(session *saml.Session) error {
	p.sessions[session.ID] = session
	return nil
}

func (p *LDAPSessProvider) DestroySession(sessID string) error {
	delete(p.sessions, sessID)
	return nil
}
