package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/api"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:  "rdpgw",
	Long: "Remote Desktop Gateway",
}

var (
	configFile string
)

var conf config.Configuration

func main() {
	// get config
	cmd.PersistentFlags().StringVarP(&configFile, "conf", "c", "rdpgw.yaml", "config file (json, yaml, ini)")
	conf = config.Load(configFile)

	api := &api.Config{
		GatewayAddress:       conf.Server.GatewayAddress,
		SessionKey:           []byte(conf.Server.SessionKey),
		SessionEncryptionKey: []byte(conf.Server.SessionEncryptionKey),
		Hosts:                conf.Server.Hosts,
		NetworkAutoDetect:    conf.Client.NetworkAutoDetect,
		UsernameTemplate:     conf.Client.UsernameTemplate,
		BandwidthAutoDetect:  conf.Client.BandwidthAutoDetect,
		ConnectionType:       conf.Client.ConnectionType,
		SplitUserDomain:      conf.Client.SplitUserDomain,
		DefaultDomain:        conf.Client.DefaultDomain,
	}
	api.NewApi()

	if conf.Server.CertFile == "" || conf.Server.KeyFile == "" {
		log.Fatal("Both certfile and keyfile need to be specified")
	}

	//mux := http.NewServeMux()
	//mux.HandleFunc("*", HelloServer)

	log.Printf("Starting remote desktop gateway server")

	cfg := &tls.Config{}
	tlsDebug := os.Getenv("SSLKEYLOGFILE")
	if tlsDebug != "" {
		w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
		}
		log.Printf("Key log file set to: %s", tlsDebug)
		cfg.KeyLogWriter = w
	}

	cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	server := http.Server{
		Addr:         ":" + strconv.Itoa(conf.Server.Port),
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	// create the gateway
	handlerConfig := protocol.ServerConf{
		IdleTimeout:   conf.Caps.IdleTimeout,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		RedirectFlags: protocol.RedirectFlags{
			Clipboard:  conf.Caps.EnableClipboard,
			Drive:      conf.Caps.EnableDrive,
			Printer:    conf.Caps.EnablePrinter,
			Port:       conf.Caps.EnablePort,
			Pnp:        conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll:  conf.Caps.RedirectAll,
		},
		SendBuf:            conf.Server.SendBuf,
		ReceiveBuf:         conf.Server.ReceiveBuf,
		PermitClientSubnet: conf.Server.PermitClientSubnet,
	}
	gw := protocol.Gateway{
		ServerConf: &handlerConfig,
	}

	http.Handle("/remoteDesktopGateway/", common.EnrichContext(http.HandlerFunc(gw.HandleGatewayProtocol)))
	http.Handle("/connect", common.EnrichContext(api.Authenticated(http.HandlerFunc(api.HandleDownload))))
	http.Handle("/metrics", promhttp.Handler())

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
