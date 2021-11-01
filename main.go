// Ozgur Demir <ozgurcd@gmail.com>

package main

import (
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	namespace = "ds_exporter"
)

var (
	server       string
	startTLS     bool
	bindDn       string
	bindPassword string
)

// DSData stores metrics from 389DS
type DSData struct {
	up                         int
	anonymousbinds             float64
	unauthbinds                float64
	simpleauthbinds            float64
	strongauthbinds            float64
	bindsecurityerrors         float64
	inops                      float64
	readops                    float64
	compareops                 float64
	addentryops                float64
	removeentryops             float64
	modifyentryops             float64
	modifyrdnops               float64
	searchops                  float64
	onelevelsearchops          float64
	wholesubtreesearchops      float64
	referrals                  float64
	securityerrors             float64
	errors                     float64
	connections                float64
	connectionseq              float64
	connectionsinmaxthreads    float64
	connectionsmaxthreadscount float64
	bytesrecv                  float64
	bytessent                  float64
	entriesreturned            float64
	referralsreturned          float64
	cacheentries               float64
	cachehits                  float64
}

// Exporter stores metrics from 389DS
type Exporter struct {
	up                         *prometheus.Desc
	anonymousbinds             *prometheus.Desc
	unauthbinds                *prometheus.Desc
	simpleauthbinds            *prometheus.Desc
	strongauthbinds            *prometheus.Desc
	bindsecurityerrors         *prometheus.Desc
	inops                      *prometheus.Desc
	readops                    *prometheus.Desc
	compareops                 *prometheus.Desc
	addentryops                *prometheus.Desc
	removeentryops             *prometheus.Desc
	modifyentryops             *prometheus.Desc
	modifyrdnops               *prometheus.Desc
	searchops                  *prometheus.Desc
	onelevelsearchops          *prometheus.Desc
	wholesubtreesearchops      *prometheus.Desc
	referrals                  *prometheus.Desc
	securityerrors             *prometheus.Desc
	errors                     *prometheus.Desc
	connections                *prometheus.Desc
	connectionseq              *prometheus.Desc
	connectionsinmaxthreads    *prometheus.Desc
	connectionsmaxthreadscount *prometheus.Desc
	bytesrecv                  *prometheus.Desc
	bytessent                  *prometheus.Desc
	entriesreturned            *prometheus.Desc
	referralsreturned          *prometheus.Desc
	cacheentries               *prometheus.Desc
	cachehits                  *prometheus.Desc
}

// NewExporter returns an initialized exporter
func NewExporter() *Exporter {
	return &Exporter{
		up: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "up"),
			"Whether the last scrape was able to connect to the server",
			nil,
			nil,
		),

		anonymousbinds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "anonymousbinds"),
			"Number of Anonymous Binds",
			nil,
			nil,
		),

		unauthbinds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "unauthbinds"),
			"Number of Unauth Binds",
			nil,
			nil,
		),

		simpleauthbinds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "simpleauthbinds"),
			"Number of Simple Auth Binds",
			nil,
			nil,
		),

		strongauthbinds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "strongauthbinds"),
			"Number of Strong Auth Binds",
			nil,
			nil,
		),

		bindsecurityerrors: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bindsecurityerrors"),
			"Number of Bind Security Errors",
			nil,
			nil,
		),

		inops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "inops"),
			"Number of All Requests",
			nil,
			nil,
		),

		readops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "readops"),
			"Number of Read Operations",
			nil,
			nil,
		),

		compareops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "compareops"),
			"Number of Compare Operations",
			nil,
			nil,
		),

		addentryops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "addentryops"),
			"Number of Add Entry Operations",
			nil,
			nil,
		),

		removeentryops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "removeentryops"),
			"Number of Remove Entry Operations",
			nil,
			nil,
		),

		modifyentryops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "modifyentryops"),
			"Number of Modify Entry Operations",
			nil,
			nil,
		),

		modifyrdnops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "modifyrdnops"),
			"Number of Modify RDN Operations",
			nil,
			nil,
		),

		searchops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "searchops"),
			"Number of LDAP Search Requests",
			nil,
			nil,
		),

		onelevelsearchops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "onelevelsearchops"),
			"Number of one-level Search Requests",
			nil,
			nil,
		),

		wholesubtreesearchops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "wholesubtreesearchops"),
			"Number of subtree-level Search Requests",
			nil,
			nil,
		),

		referrals: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "referrals"),
			"Number of LDAP referrals",
			nil,
			nil,
		),

		securityerrors: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "securityerrors"),
			"Number of Security Errors",
			nil,
			nil,
		),

		errors: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "errors"),
			"Number of Errors",
			nil,
			nil,
		),

		connections: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "connections"),
			"Number of Connections in Open State at the sampling time",
			nil,
			nil,
		),

		connectionseq: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "connectionseq"),
			"Total Number of Connections opened",
			nil,
			nil,
		),

		connectionsinmaxthreads: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "connectionsinmaxthreads"),
			"Number of connections that are currently in a max thread state",
			nil,
			nil,
		),

		connectionsmaxthreadscount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "connectionsmaxthreadscount"),
			"Number of connectionsmaxthreadscount",
			nil,
			nil,
		),

		bytesrecv: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bytesrecv"),
			"Total number of bytes received",
			nil,
			nil,
		),

		bytessent: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "bytessent"),
			"Total number of bytes sent",
			nil,
			nil,
		),

		entriesreturned: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "entriesreturned"),
			"Number of Entries Returned",
			nil,
			nil,
		),

		referralsreturned: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "referralsreturned"),
			"Number of Referrals Returned",
			nil,
			nil,
		),

		cacheentries: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "cacheentries"),
			"Number of Cache Entries",
			nil,
			nil,
		),

		cachehits: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "cachehits"),
			"Number of Cache Hits",
			nil,
			nil,
		),
	}
}

// Describe soyle boyle
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.up
	ch <- e.anonymousbinds
	ch <- e.unauthbinds
	ch <- e.simpleauthbinds
	ch <- e.strongauthbinds
	ch <- e.bindsecurityerrors
	ch <- e.inops
	ch <- e.readops
	ch <- e.compareops
	ch <- e.addentryops
	ch <- e.removeentryops
	ch <- e.modifyentryops
	ch <- e.modifyrdnops
	ch <- e.searchops
	ch <- e.onelevelsearchops
	ch <- e.wholesubtreesearchops
	ch <- e.referrals
	ch <- e.securityerrors
	ch <- e.errors
	ch <- e.connections
	ch <- e.connectionseq
	ch <- e.connectionsinmaxthreads
	ch <- e.connectionsmaxthreadscount
	ch <- e.bytesrecv
	ch <- e.bytessent
	ch <- e.entriesreturned
	ch <- e.referralsreturned
	ch <- e.cacheentries
	ch <- e.cachehits
}

// Collect reads stats from LDAP connection object into Prometheus objects
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	data, err := getStats(server, startTLS, bindDn, bindPassword)
	ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, float64(data.up))
	if err != nil {
		log.WithError(err).Error("scrape failed")
	}

	ch <- prometheus.MustNewConstMetric(e.anonymousbinds, prometheus.CounterValue, data.anonymousbinds)
	ch <- prometheus.MustNewConstMetric(e.unauthbinds, prometheus.CounterValue, data.unauthbinds)
	ch <- prometheus.MustNewConstMetric(e.simpleauthbinds, prometheus.CounterValue, data.simpleauthbinds)
	ch <- prometheus.MustNewConstMetric(e.strongauthbinds, prometheus.CounterValue, data.strongauthbinds)
	ch <- prometheus.MustNewConstMetric(e.bindsecurityerrors, prometheus.CounterValue, data.bindsecurityerrors)
	ch <- prometheus.MustNewConstMetric(e.inops, prometheus.CounterValue, data.inops)
	ch <- prometheus.MustNewConstMetric(e.readops, prometheus.CounterValue, data.readops)
	ch <- prometheus.MustNewConstMetric(e.compareops, prometheus.CounterValue, data.compareops)
	ch <- prometheus.MustNewConstMetric(e.addentryops, prometheus.CounterValue, data.addentryops)
	ch <- prometheus.MustNewConstMetric(e.removeentryops, prometheus.CounterValue, data.removeentryops)
	ch <- prometheus.MustNewConstMetric(e.modifyentryops, prometheus.CounterValue, data.modifyentryops)
	ch <- prometheus.MustNewConstMetric(e.modifyrdnops, prometheus.CounterValue, data.modifyrdnops)
	ch <- prometheus.MustNewConstMetric(e.searchops, prometheus.CounterValue, data.searchops)
	ch <- prometheus.MustNewConstMetric(e.onelevelsearchops, prometheus.CounterValue, data.onelevelsearchops)
	ch <- prometheus.MustNewConstMetric(e.wholesubtreesearchops, prometheus.CounterValue, data.wholesubtreesearchops)
	ch <- prometheus.MustNewConstMetric(e.referrals, prometheus.CounterValue, data.referrals)
	ch <- prometheus.MustNewConstMetric(e.securityerrors, prometheus.CounterValue, data.securityerrors)
	ch <- prometheus.MustNewConstMetric(e.errors, prometheus.CounterValue, data.errors)
	ch <- prometheus.MustNewConstMetric(e.connections, prometheus.CounterValue, data.connections)
	ch <- prometheus.MustNewConstMetric(e.connectionseq, prometheus.CounterValue, data.connectionseq)
	ch <- prometheus.MustNewConstMetric(e.connectionsinmaxthreads, prometheus.CounterValue, data.connectionsinmaxthreads)
	ch <- prometheus.MustNewConstMetric(e.connectionsmaxthreadscount, prometheus.CounterValue, data.connectionsmaxthreadscount)
	ch <- prometheus.MustNewConstMetric(e.bytesrecv, prometheus.CounterValue, data.bytesrecv)
	ch <- prometheus.MustNewConstMetric(e.bytessent, prometheus.CounterValue, data.bytessent)
	ch <- prometheus.MustNewConstMetric(e.entriesreturned, prometheus.CounterValue, data.entriesreturned)
	ch <- prometheus.MustNewConstMetric(e.referralsreturned, prometheus.CounterValue, data.referralsreturned)
	ch <- prometheus.MustNewConstMetric(e.cacheentries, prometheus.CounterValue, data.cacheentries)
	ch <- prometheus.MustNewConstMetric(e.cachehits, prometheus.CounterValue, data.cachehits)
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("LookupEnvOrBool[%s]: %v", key, err)
		}
		return v
	}
	return defaultVal
}

func main() {
	var (
		listenAddress    = flag.String("web.listen-address", LookupEnvOrString("DS_LISTEN_ADDRESS", ":9313"), "Address to listen on for web interface and telemetry (DS_LISTEN_ADDRESS)")
		metricsPath      = flag.String("web.telemetry-path", LookupEnvOrString("DS_TELEMETRY_PATH", "/metrics"), "Path under which to expose metrics (DS_TELEMETRY_PATH)")
		ldapServer       = flag.String("ldap.ServerURL", LookupEnvOrString("DS_SERVER_URL", "ldap://localhost"), "URL of the target LDAP server (DS_SERVER_URL)")
		ldapStartTLS     = flag.Bool("ldap.StartTLS", LookupEnvOrBool("DS_STARTTLS", true), "Use StartTLS (DS_STARTTLS)")
		ldapBindDN       = flag.String("ldap.BindDN", LookupEnvOrString("DS_BINDDN", ""), "DN to bind to the target LDAP server (DS_BINDDN)")
		ldapBindPassword = flag.String("ldap.BindPassword", LookupEnvOrString("DS_BINDPASSWORD", ""), "Password to bind to the target LDAP server (DS_BINDPASSWORD)")
	)
	flag.Parse()

	server = *ldapServer
	startTLS = *ldapStartTLS
	bindDn = *ldapBindDN
	bindPassword = *ldapBindPassword

	log.Infoln("Connecting to LDAP Server: ", *ldapServer)

	prometheus.MustRegister(NewExporter())

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>389-DS Exporter</title></head>
             <body>
             <h1>389-DS Exporter</h1>
             <p>For the metrics: Click <a href='` + *metricsPath + `'>here</a></p>
             </body>
             </html>`))
	})
	log.Infoln("Starting HTTP server on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
