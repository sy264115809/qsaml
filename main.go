package main

import (
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofly/saml"
)

const (
	cookieName = "qsaml"
)

func readSPConfig(spConfDir string) (map[string]*saml.Metadata, error) {
	metas := make(map[string]*saml.Metadata)
	err := filepath.Walk(spConfDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()

			meta := &saml.Metadata{}
			err = xml.NewDecoder(f).Decode(meta)
			if err != nil {
				return err
			}
			metas[meta.EntityID] = meta
		}
		return nil
	})
	return metas, err
}

func handleSSO(assetsPrefix string, tmpl *template.Template,
	idp *saml.IdentityProvider, sessProvider *LDAPSessProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sessionID string
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			if time.Now().After(cookie.Expires) {
				err = sessProvider.DestroySession(cookie.Value)
				if err != nil {
					log.Printf("LDAPSessProvider.DestroySession(%s) with error: %s\n", cookie.Value, err)
				}
			} else {
				sessionID = cookie.Value
			}
		}
		err = r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		username := strings.TrimSpace(r.PostFormValue("username"))
		password := strings.TrimSpace(r.PostFormValue("password"))
		if username != "" {
			session, err := sessProvider.GetSessionByUsernameAndPassword(username, password)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				log.Printf("LDAPSessProvider.GetSessionByUsernameAndPassword(%s) with error: %s\n", username, err)
				return
			}
			err = sessProvider.SetSession(session)
			if err != nil {
				log.Printf("LDAPSessProvider.SetSession(%s) with error: %s\n", session.NameID, err)
			}
			cookie = &http.Cookie{
				Name:     cookieName,
				Value:    session.ID,
				MaxAge:   int(session.ExpireTime.Sub(session.CreateTime)),
				HttpOnly: true,
				Path:     "/",
			}
			http.SetCookie(w, cookie)
			sessionID = session.ID
		}

		req, err := saml.NewIdpAuthnRequest(idp, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("请求参数不正确"))
			return
		}
		err = req.Validate()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("请求参数不正确"))
			return
		}
		if sessionID != "" {
			session, err := sessProvider.GetSessionBySessionID(sessionID)
			if err == nil {
				ssoResponse, err := req.GetSSOResponse(session)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
					return
				}
				err = tmpl.ExecuteTemplate(w, "redirect.html", map[string]interface{}{
					"AssetsPrefix": assetsPrefix,
					"URL":          ssoResponse.URL,
					"SAMLResponse": ssoResponse.SAMLResponse,
					"RelayState":   ssoResponse.RelayState,
				})
				if err != nil {
					log.Printf("tmpl.ExecuteTemplate(redirect.html) with error: %s\n", err)
				}
				return
			}
		}
		data := map[string]interface{}{
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
func main() {
	var (
		spConfDir, keyFilePath, certFilePath           string
		httpPrefix, assetsPrefix, ldapAddr, ldapBindDN string
		sessionMaxAgeSeconds                           int
	)
	flag.StringVar(&spConfDir, "sp-dir", "sp", "service provider configs directory")
	flag.StringVar(&keyFilePath, "key-path", "key.pem", "private key path")
	flag.StringVar(&certFilePath, "cert-path", "cert.pem", "certificate path")
	flag.StringVar(&httpPrefix, "http-prefix", "http://localhost:8080", "http prefix")
	flag.StringVar(&assetsPrefix, "assets-prefix", "http://localhost:8080", "assets prefix")
	flag.StringVar(&ldapAddr, "ldap-addr", "localhost:389", "ldap server address")
	flag.StringVar(&ldapBindDN, "ldap-bind-dn", "ou=People,dc=qiniu,dc=com", "ldap bind dn")
	flag.IntVar(&sessionMaxAgeSeconds, "session-max-age", 3600, "session max age in seconds")
	flag.Parse()

	serviceProviders, err := readSPConfig(spConfDir)
	if err != nil {
		log.Fatalf("Read service provider config with error: %s\n", err)
	}

	key, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.Fatalf("Read key file from %s with error: %s\n", keyFilePath, err)
	}

	cert, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		log.Fatalf("Read certificate file from %s with error: %s\n", certFilePath, err)
	}
	sessionMaxAge := time.Second * time.Duration(sessionMaxAgeSeconds)
	sessProvider := NewLDAPSessionProvider(ldapAddr, ldapBindDN, sessionMaxAge)
	idp := &saml.IdentityProvider{
		Key:              string(key),
		Certificate:      string(cert),
		MetadataURL:      fmt.Sprintf("%s/meta", httpPrefix),
		SSOURL:           fmt.Sprintf("%s/sso", httpPrefix),
		ServiceProviders: serviceProviders,
	}

	tmpl := template.Must(template.New("qsaml-templates").ParseGlob("templates/*.html"))
	http.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		encoder := xml.NewEncoder(w)
		encoder.Indent("", "  ")
		encoder.Encode(idp.Metadata())
	})
	http.HandleFunc("/sso", handleSSO(assetsPrefix, tmpl, idp, sessProvider))
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			err := sessProvider.DestroySession(cookie.Value)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
		}
		redirect := r.URL.Query().Get("redirect")
		if _, ok := serviceProviders[redirect]; !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("错误的SP"))
			return
		}
		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusFound)
	})
	http.Handle("/static/", http.FileServer(http.Dir(".")))
	http.ListenAndServe(":8080", nil)
}
