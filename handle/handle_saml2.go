package handle

import (
	"encoding/base64"
	"encoding/xml"
	"html/template"
	"log"
	"net/http"

	"github.com/gofly/qsaml/session"
	"github.com/gofly/saml"
)

type SessionProvider interface {
	GetSessionByUsernameAndPassword(username, password string) (*saml.Session, error)
	GetSessionBySessionID(sessID string) (*saml.Session, error)
	SetSession(session *saml.Session) error
	DestroySession(sessID string) error
}

func HandleSAMLMeta(idp *saml.IdentityProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")
		encoder.Encode(idp.Metadata())
	}
}

func HandleSAMLSSO(assetsPrefix string, tmpl *template.Template,
	idp *saml.IdentityProvider, sessProvider SessionProvider) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		req, err := saml.NewIdpAuthnRequest(idp, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("请求参数不正确：" + err.Error()))
			return
		}
		err = req.Validate()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if err == saml.ErrRequestExpired {
				w.Write([]byte("请求已过期，请返回重新登录"))
				return
			}
			w.Write([]byte("请求参数不正确：" + err.Error()))
			return
		}
		var (
			sessID string
			errMsg string
		)
		ok, cookie, err := LoginCookie(r, sessProvider)
		if err != nil {
			if err == session.ErrBindFailed {
				w.WriteHeader(http.StatusUnauthorized)
				errMsg = "用户名或密码错误"
			} else if err != http.ErrNoCookie {
				w.WriteHeader(http.StatusInternalServerError)
				errMsg = "登录出错：" + err.Error()
				log.Printf("login with error: %s\n", err)
			}
		} else if ok {
			http.SetCookie(w, cookie)
			sessID = cookie.Value
		}
		if sessID != "" {
			session, err := sessProvider.GetSessionBySessionID(sessID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				errMsg = "登录出错：" + err.Error()
				log.Printf("sessProvider.GetSessionBySessionID(%s) with error: %s\n", sessID, err)
			} else {
				ssoResponse, err := req.GetSSOResponse(session)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					errMsg = "登录出错：" + err.Error()
					log.Printf("GetSSOResponse with error: %s\n", err)
				} else {
					err = tmpl.ExecuteTemplate(w, "redirect.html", map[string]interface{}{
						"AssetsPrefix": assetsPrefix,
						"URL":          ssoResponse.URL,
						"SAMLResponse": ssoResponse.SAMLResponse,
						"RelayState":   ssoResponse.RelayState,
					})
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						errMsg = "登录出错：" + err.Error()
						log.Printf("tmpl.ExecuteTemplate(redirect.html) with error: %s\n", err)
					} else {
						return
					}
				}
			}
		}

		data := map[string]interface{}{
			"ErrMsg":       errMsg,
			"AssetsPrefix": assetsPrefix,
			"URL":          req.IDP.SSOURL,
			"SAMLRequest":  base64.StdEncoding.EncodeToString(req.RequestBuffer),
			"RelayState":   req.RelayState,
		}
		if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
	}
}

func HandleSAMLLogout(idp *saml.IdentityProvider, sessProvider SessionProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			err := sessProvider.DestroySession(cookie.Value)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("DestroySession(%s) with error: %s\n", cookie.Value, err)
				return
			}
		}
		redirect := r.URL.Query().Get("redirect")
		if _, ok := idp.ServiceProviders[redirect]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("错误的SP"))
			return
		}
		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusFound)
	}
}
