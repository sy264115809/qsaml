package main

import (
	"encoding/base64"
	"encoding/hex"
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
	"github.com/vanackere/ldap"
)

const (
	sessionMaxAge = time.Hour
	cookieName    = "qsaml"
)

var sessions map[string]*saml.Session

func init() {
	sessions = make(map[string]*saml.Session)
}
func randomBytes(n int) []byte {
	rv := make([]byte, n)
	saml.RandReader.Read(rv)
	return rv
}

type LDAPSessProvider struct {
	ldapAddr string
	bindDN   string
}

func (p *LDAPSessProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	cookie, err := r.Cookie(cookieName)
	if err == nil {
		if session, ok := sessions[cookie.Value]; ok {
			return session
		}
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))
	ldapConn, err := ldap.DialTLS("tcp", p.ldapAddr, nil)
	if err != nil {
		log.Printf("ldap.DialTLS %s with error: \n", p.ldapAddr)
		return nil
	}
	defer ldapConn.Close()

	err = ldapConn.Bind(fmt.Sprintf("cn=%s,%s", username, p.bindDN), password)
	if err != nil {
		return nil
	}

	sessID := base64.StdEncoding.EncodeToString(randomBytes(32))
	sessions[sessID] = &saml.Session{
		ID:         sessID,
		NameID:     username,
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(sessionMaxAge),
		Index:      hex.EncodeToString(randomBytes(32)),
		UserName:   username,
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "",
		Value:    sessID,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Path:     "/",
	})
	return sessions[sessID]
}

func (p *LDAPSessProvider) DestroySession(sessID string) error {
	delete(sessions, sessID)
	return nil
}

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

func main() {
	var (
		spConfDir, keyFilePath, certFilePath, httpPrefix, assetsPrefix, ldapAddr, ldapBindDN string
	)
	flag.StringVar(&spConfDir, "sp-dir", "sp", "service provider configs directory")
	flag.StringVar(&keyFilePath, "key-path", "key.pem", "private key path")
	flag.StringVar(&certFilePath, "cert-path", "cert.pem", "certificate path")
	flag.StringVar(&httpPrefix, "http-prefix", "http://localhost:8080", "http prefix")
	flag.StringVar(&assetsPrefix, "assets-prefix", "http://localhost:8080", "assets prefix")
	flag.StringVar(&ldapAddr, "ldap-addr", "localhost:389", "ldap server address")
	flag.StringVar(&ldapBindDN, "ldap-bind-dn", "ou=People,dc=qiniu,dc=com", "ldap bind dn")
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

	sessProvider := &LDAPSessProvider{ldapAddr, ldapBindDN}
	provider := &saml.IdentityProvider{
		Key:              string(key),
		Certificate:      string(cert),
		MetadataURL:      fmt.Sprintf("%s/meta", httpPrefix),
		SSOURL:           fmt.Sprintf("%s/sso", httpPrefix),
		ServiceProviders: serviceProviders,
		SessionProvider:  sessProvider,
	}

	tmpl := template.Must(template.New("saml-post-form").ParseGlob("templates/*.html"))
	http.HandleFunc("/meta", provider.ServeMetadata)
	http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			if time.Now().Before(cookie.Expires) {
				provider.ServeSSO(w, r)
				return
			}
		}
		err = r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		if len(r.PostFormValue("username")) > 0 {
			provider.ServeSSO(w, r)
			return
		}

		req, err := saml.NewIdpAuthnRequest(provider, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("请求参数不正确"))
			return
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
	})
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
