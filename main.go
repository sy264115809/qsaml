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

	"github.com/gofly/saml"
)

var (
	key, cert []byte
	meta      *saml.Metadata
	prefix    string
)

type SessProvider struct {
}

func (p *SessProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{
		ID:        "1234",
		NameID:    "zhenglixin",
		UserName:  "zhenglixin",
		UserEmail: "zhenglixin@qiniu.com",
		Index:     "145",
	}
}

func sendLoginForm(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest, toast string) {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<html>` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="text" name="user" placeholder="user" value="" />` +
		`<input type="password" name="password" placeholder="password" value="" />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Log In" />` +
		`</form>` +
		`</html>`))
	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         req.IDP.SSOURL,
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
	}

	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}
func init() {
	flag.StringVar(&prefix, "prefix", "", "prefix")
	flag.Parse()
	data, err := ioutil.ReadFile("samlsp.xml")
	if err != nil {
		panic(err)
	}
	meta = &saml.Metadata{}
	err = xml.Unmarshal(data, meta)
	if err != nil {
		panic(err)
	}

	key, err = ioutil.ReadFile("saml.key")
	if err != nil {
		panic(err)
	}

	cert, err = ioutil.ReadFile("saml.crt")
	if err != nil {
		panic(err)
	}
}
func main() {
	provider := &saml.IdentityProvider{
		Key:         string(key),
		Certificate: string(cert),
		MetadataURL: fmt.Sprintf("%s/meta", prefix),
		SSOURL:      fmt.Sprintf("%s/sso", prefix),
		ServiceProviders: map[string]*saml.Metadata{
			meta.EntityID: meta,
		},
		SessionProvider: &SessProvider{},
	}
	http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("user") != "" {
			provider.ServeSSO(w, r)
			return
		}
		req, err := saml.NewIdpAuthnRequest(provider, r)
		if err != nil {
			log.Println(err)
			return
		}
		sendLoginForm(w, r, req, "Login")
	})
	http.HandleFunc("/meta", provider.ServeMetadata)
	http.ListenAndServe(":8080", nil)
}
