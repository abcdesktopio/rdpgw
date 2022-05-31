package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

const (
	RdpGwSession = "RDPGWSESSION"
	MaxAge       = 120
)

type Config struct {
	ClientIPAddress      string
	SessionKey           []byte
	SessionEncryptionKey []byte
	store                *sessions.CookieStore
	stateStore           *cache.Cache
	Hosts                []string
	GatewayAddress       string
	UsernameTemplate     string
	NetworkAutoDetect    int
	BandwidthAutoDetect  int
	ConnectionType       int
	SplitUserDomain      bool
	DefaultDomain        string
}

func (c *Config) NewApi() {
	if len(c.SessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(c.Hosts) < 1 {
		log.Fatal("Not enough hosts to connect to specified")
	}
	c.store = sessions.NewCookieStore(c.SessionKey, c.SessionEncryptionKey)
	c.stateStore = cache.New(time.Minute*2, 5*time.Minute)
}

func (c *Config) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s, found := c.stateStore.Get(state)
	if !found {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	url := s.(string)

	http.Redirect(w, r, url, http.StatusFound)
}

func (c *Config) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := c.store.Get(r, RdpGwSession)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), "preferred_username", session.Values["preferred_username"])
		ctx = context.WithValue(ctx, "access_token", session.Values["access_token"])

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *Config) HandleDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userName, ok := ctx.Value("preferred_username").(string)

	if !ok {
		log.Printf("preferred_username not found in context")
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	// do a round robin selection for now
	rand.Seed(time.Now().Unix())
	host := c.Hosts[rand.Intn(len(c.Hosts))]
	host = strings.Replace(host, "{{ preferred_username }}", userName, 1)

	// split the username into user and domain
	var user = userName
	var domain = c.DefaultDomain
	if c.SplitUserDomain {
		creds := strings.SplitN(userName, "@", 2)
		user = creds[0]
		if len(creds) > 1 {
			domain = creds[1]
		}
	}

	render := user
	if c.UsernameTemplate != "" {
		render = fmt.Sprintf(c.UsernameTemplate)
		render = strings.Replace(render, "{{ username }}", user, 1)
		if c.UsernameTemplate == render {
			log.Printf("Invalid username template. %s == %s", c.UsernameTemplate, user)
			http.Error(w, errors.New("invalid server configuration").Error(), http.StatusInternalServerError)
			return
		}
	}

	// authenticated
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")
	data := "full address:s:" + host + "\r\n" +
		"gatewayhostname:s:" + c.GatewayAddress + "\r\n" +
		"gatewaycredentialssource:i:5\r\n" +
		"gatewayusagemethod:i:1\r\n" +
		"gatewayprofileusagemethod:i:1\r\n" +
		"networkautodetect:i:" + strconv.Itoa(c.NetworkAutoDetect) + "\r\n" +
		"bandwidthautodetect:i:" + strconv.Itoa(c.BandwidthAutoDetect) + "\r\n" +
		"connection type:i:" + strconv.Itoa(c.ConnectionType) + "\r\n" +
		"username:s:" + render + "\r\n" +
		"domain:s:" + domain + "\r\n" +
		"bitmapcachesize:i:32000\r\n" +
		"smart sizing:i:1\r\n"

	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(data))
}
