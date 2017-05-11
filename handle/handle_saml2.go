package handle

import (
	"encoding/base64"
	"encoding/xml"
	"html/template"
	"log"
	"net/http"

	"strconv"

	"github.com/gofly/qsaml/session"
	"github.com/gofly/saml"
)

type SessionProvider interface {
	GetSessionByUsernameAndPassword(username, password string) (*saml.Session, error)
	GetSessionBySessionID(sessID string) (*saml.Session, error)
	SetSession(sessID string, session *saml.Session) error
	DestroySession(sessID string) error
}

type samlSSOResult struct {
	ErrMsg       string
	AssetsPrefix string
	LoginName    string
	Destination  string
	Retry        int
	SAMLReq      struct {
		URL                 string
		SAMLRequest         string
		SAMLRequestCompress string
		RelayState          string
	}
	SAMLResp *saml.SSOResponse
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
		req, err := samlRequest(r, idp)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if err == saml.ErrRequestExpired {
				w.Write([]byte("请求已过期，请返回重新登录"))
				return
			}
			w.Write([]byte("请求参数不正确：" + err.Error()))
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("请求不正确，请返回重新登录"))
			return
		}

		var (
			errCode int
			data    = samlSSOResult{
				AssetsPrefix: assetsPrefix,
				Retry:        1,
			}
		)

		defer func() {
			data.SAMLReq.URL = req.IDP.SSOURL
			data.SAMLReq.SAMLRequest = base64.StdEncoding.EncodeToString(req.RequestBuffer)
			data.SAMLReq.SAMLRequestCompress = flateCompress(req.RequestBuffer)
			data.SAMLReq.RelayState = req.RelayState
			data.Destination = destination(req.ServiceProviderMetadata.EntityID)

			if err != nil {
				data.ErrMsg = "登录出错：" + err.Error()
				if errCode == 0 {
					errCode = http.StatusInternalServerError
				}
				w.WriteHeader(errCode)
			}

			if err := tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
		}()

		var sess *saml.Session
		switch r.Method {
		// GET 请求一定是用户主动请求登录页面，仅需判断是否存在合法的 session，存在则允许自动以该身份跳转;
		case http.MethodGet:
			if cookie, err := r.Cookie(cookieName); err == nil {
				sess, err = sessProvider.GetSessionBySessionID(cookie.Value)
			}
			// 黑科技：如果 data.SAMLResp == nil, 最多尝试刷新页面 2 次, 为的是撞大运到另一台有可能有该 session 的实例
			retry, _ := strconv.Atoi(r.URL.Query().Get("retry"))
			data.Retry = (retry + 1) % 3

		// POST 请求一定是来自登录页面的表单提交，仅需处理登录逻辑;
		case http.MethodPost:
			var cookie *http.Cookie
			sess, cookie, err = login(r, sessProvider)
			if err != nil {
				if err == session.ErrBindFailed {
					err = ErrInvalidCredentials
				}
				if err == ErrInvalidCredentials {
					errCode = http.StatusUnauthorized
				}
				return
			}
			http.SetCookie(w, cookie)
		}

		if sess != nil {
			if data.SAMLResp, err = req.GetSSOResponse(sess); err == nil {
				data.LoginName = sess.UserName
			}
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
			cookie.Value = ""
			cookie.Path = "/"
			cookie.MaxAge = -1
			cookie.Secure = true
			http.SetCookie(w, cookie)
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
