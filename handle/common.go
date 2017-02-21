package handle

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	cookieName = "qsaml"
)

func LoginCookie(r *http.Request, sessProvider SessionProvider) (bool, *http.Cookie, error) {
	cookie, err := r.Cookie(cookieName)
	if err == nil {
		if time.Now().UTC().After(cookie.Expires) {
			err = sessProvider.DestroySession(cookie.Value)
			if err != nil {
				log.Printf("LDAPSessProvider.DestroySession(%s) with error: %s\n", cookie.Value, err)
			}
		} else {
			return false, cookie, nil
		}
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))
	if username != "" && password != "" {
		sess, err := sessProvider.GetSessionByUsernameAndPassword(username, password)
		if err != nil {
			return false, nil, err
		}
		err = sessProvider.SetSession(sess)
		if err != nil {
			err = fmt.Errorf("LDAPSessProvider.SetSession(%s) with error: %s", sess.NameID, err)
			return false, nil, err
		}
		return true, &http.Cookie{
			Name:     cookieName,
			Value:    sess.ID,
			MaxAge:   int(sess.ExpireTime.Sub(sess.CreateTime).Seconds()),
			HttpOnly: true,
			Path:     "/",
		}, nil
	}
	return false, nil, http.ErrNoCookie
}
