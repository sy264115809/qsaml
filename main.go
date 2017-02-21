package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gofly/qsaml/handle"
	"github.com/gofly/qsaml/session"
	"github.com/gofly/saml"
)

var (
	spConfDir                string
	httpPrefix, assetsPrefix string
	ldapAddr, ldapBindDN     string
	sessionMaxAgeSeconds     int
	key, cert                []byte
)

func init() {
	var (
		keyFilePath  string
		certFilePath string
		err          error
	)

	flag.StringVar(&spConfDir, "sp-dir", "sp", "service provider configs directory")
	flag.StringVar(&keyFilePath, "key-path", "key.pem", "private key path")
	flag.StringVar(&certFilePath, "cert-path", "cert.pem", "certificate path")
	flag.StringVar(&httpPrefix, "http-prefix", "http://localhost:8080", "http prefix")
	flag.StringVar(&assetsPrefix, "assets-prefix", "", "assets prefix, same as -http-prefix if it's empty")
	flag.StringVar(&ldapAddr, "ldap-addr", "localhost:389", "ldap server address")
	flag.StringVar(&ldapBindDN, "ldap-bind-dn", "ou=People,dc=qiniu,dc=com", "ldap bind dn")
	flag.IntVar(&sessionMaxAgeSeconds, "session-max-age", 3600, "session max age in seconds")
	flag.Parse()

	if assetsPrefix == "" {
		assetsPrefix = httpPrefix
	}

	key, err = ioutil.ReadFile(keyFilePath)
	if err != nil {
		log.Fatalf("Read key file from %s with error: %s\n", keyFilePath, err)
	}

	cert, err = ioutil.ReadFile(certFilePath)
	if err != nil {
		log.Fatalf("Read certificate file from %s with error: %s\n", certFilePath, err)
	}
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
	serviceProviders, err := readSPConfig(spConfDir)
	if err != nil {
		log.Fatalf("Read service provider config with error: %s\n", err)
	}

	sessionMaxAge := time.Second * time.Duration(sessionMaxAgeSeconds)
	idp := &saml.IdentityProvider{
		Key:              string(key),
		Certificate:      string(cert),
		MetadataURL:      fmt.Sprintf("%s/meta", httpPrefix),
		SSOURL:           fmt.Sprintf("%s/sso", httpPrefix),
		ServiceProviders: serviceProviders,
	}

	sessProvider := session.NewLDAPSessionProvider(ldapAddr, ldapBindDN, sessionMaxAge)
	tmpl := template.Must(template.New("qsaml-templates").ParseGlob("templates/*.html"))

	// for saml2
	http.HandleFunc("/saml2/meta", handle.HandleSAMLMeta(idp))
	http.HandleFunc("/saml2/sso", handle.HandleSAMLSSO(assetsPrefix, tmpl, idp, sessProvider))
	http.HandleFunc("/saml2/logout", handle.HandleSAMLLogout(idp, sessProvider))

	// for cas
	http.HandleFunc("/cas/login", handle.HandleCASLogin(tmpl, sessProvider))
	http.HandleFunc("/cas/serviceValidate", handle.HandleCASServiceValidate())

	// for static
	http.Handle("/static/", http.FileServer(http.Dir(".")))

	http.ListenAndServe(":8080", nil)
}
