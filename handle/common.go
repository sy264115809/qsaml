package handle

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"crypto/md5"

	"net/url"

	"github.com/gofly/qsaml/session"
	"github.com/gofly/saml"
)

const (
	cookieName = "qsaml"
)

var (
	ErrInvalidCredentials = errors.New("用户名或密码错误")
)

func login(r *http.Request, sessProvider SessionProvider) (sess *saml.Session, cookie *http.Cookie, err error) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))

	if username == "" || password == "" {
		err = ErrInvalidCredentials
		return
	}

	sess, err = sessProvider.GetSessionByUsernameAndPassword(username, password)
	if err != nil {
		if err == session.ErrBindFailed {
			err = ErrInvalidCredentials
			log.Printf("%s login with invalid password\n", username)
		}
		return
	}

	nameMD5 := fmt.Sprintf("%x", md5.Sum([]byte(username)))
	sessID := sess.ID + nameMD5
	if c, err := r.Cookie(cookieName); err == nil {
		if val := c.Value; strings.HasSuffix(val, nameMD5) {
			sessID = val + nameMD5
		}
	}

	err = sessProvider.SetSession(sessID, sess)
	if err != nil {
		err = fmt.Errorf("LDAPSessProvider.SetSession(%s) with error: %s", sess.NameID, err)
		return
	}

	cookie = &http.Cookie{
		Name:     cookieName,
		Value:    sessID,
		MaxAge:   int(sess.ExpireTime.Sub(sess.CreateTime).Seconds()),
		HttpOnly: true,
		Path:     "/",
	}
	return
}

func samlRequest(r *http.Request, idp *saml.IdentityProvider) (req *saml.IdpAuthnRequest, err error) {
	req, err = saml.NewIdpAuthnRequest(idp, r)
	if err != nil {
		return
	}

	err = req.Validate()
	return
}

func getSAMLSession(r *http.Request, sessProvider SessionProvider) (sess *saml.Session, err error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	return sessProvider.GetSessionBySessionID(cookie.Value)
}

func destination(entityID string) string {
	switch {
	case strings.Contains(entityID, "salesforce") || strings.Contains(entityID, "crm"):
		return "七牛 CRM 系统"
	case strings.Contains(entityID, "successfactors"):
		return "七牛 HR 系统"
	default:
		if u, err := url.Parse(entityID); err == nil {
			return u.Path
		}
		return entityID
	}
}

func flateCompress(src []byte) string {
	sw := bytes.NewBufferString("")
	fw, _ := flate.NewWriter(sw, flate.BestSpeed)
	io.Copy(fw, bytes.NewReader(src))
	fw.Close()
	return base64.StdEncoding.EncodeToString(sw.Bytes())
}
