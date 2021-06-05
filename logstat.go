package main

import (
	"container/ring"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Statistics struct {
	TotalCount prometheus.Counter
}

var (
	BUFFER       *ring.Ring
	BUFFER_SIZE  = 1000
	HTTP_PORT    = 8080
	MAJOR        = 0
	MINOR        = 0
	REGISTRY     *prometheus.Registry
	REVISION     = 20210603
	SOURCE_COUNT = make(map[string]*prometheus.CounterVec)
	SOURCE_BYTES = make(map[string]*prometheus.CounterVec)
	SYSLOG_PORT  = 1514
	TOTAL_BYTES  *prometheus.CounterVec
	TOTAL_COUNT  *prometheus.CounterVec
	TOTAL_FAILS  prometheus.Counter
)

func init() {
	REGISTRY = prometheus.NewRegistry()
	TOTAL_BYTES = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_bytes_total", Help: "Total bytes processed"}, []string{"app", "severity", "facility"})
	TOTAL_COUNT = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_count_total", Help: "Total messages processed"}, []string{"app", "severity", "facility"})
	TOTAL_FAILS = promauto.NewCounter(prometheus.CounterOpts{Name: "logstat_fails_total", Help: "Total failed messages"})
	REGISTRY.Register(TOTAL_COUNT)
	REGISTRY.Register(TOTAL_BYTES)
	REGISTRY.Register(TOTAL_FAILS)
	BUFFER = ring.New(BUFFER_SIZE)
}

func version() string {
	return fmt.Sprintf("logstat %d.%d.%d\n", MAJOR, MINOR, REVISION)
}

func httpRoot(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(res, "%s\n", version())
	fmt.Fprintf(res, "%19s:%13s:%10s:%15s:%30s:%12s:\"%s\"\n", "timestamp", "severity", "facility", "source", "host", "appl", "message")
	fmt.Fprintf(res, "--\n")

	BUFFER.Do(func(p interface{}) {
		if p == nil {
			return
		}
		m := p.(SyslogMessage)
		fmt.Fprintf(res, "%19s:%13s:%10s:%15s:%30s:%12s:\"%s\"\n", m.Timestamp.Format("2006-01-02 15:04:05"), m.Severity(), m.Facility(), m.Source, m.Host, m.Application, m.Message)
	})
}

func httpServer(port int) *http.Server {
	m := http.NewServeMux()

	m.Handle("/metrics", promhttp.HandlerFor(REGISTRY, promhttp.HandlerOpts{}))
	m.HandleFunc("/", httpRoot)

	s := http.Server{
		Addr:    fmt.Sprintf(":%v", port),
		Handler: m,
	}

	return &s
}

type SyslogMessage struct {
	Priority    int
	Timestamp   time.Time
	Host        string
	Application string
	Message     string
	Source      string
}

type SyslogMessageSeverity int

func (s SyslogMessageSeverity) String() string {
	switch s {
	case 0:
		return "emergency"
	case 1:
		return "alert"
	case 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "informational"
	case 7:
		return "debug"
	default:
		return "unknown"
	}
}

type SyslogMessageFacility int

func (f SyslogMessageFacility) String() string {
	switch f {
	case 0:
		return "kernel"
	case 1:
		return "user"
	case 2:
		return "mail"
	case 3:
		return "system"
	case 4:
		return "security"
	case 5:
		return "internal"
	case 6:
		return "lineprinter"
	case 7:
		return "networknews"
	case 8:
		return "uucp"
	case 9:
		return "clock"
	case 10:
		return "security"
	case 11:
		return "ftp"
	case 12:
		return "ntp"
	case 13:
		return "logaudit"
	case 14:
		return "logalert"
	case 15:
		return "clock"
	case 16:
		return "local0"
	case 17:
		return "local1"
	case 18:
		return "local2"
	case 19:
		return "local3"
	case 20:
		return "local4"
	case 21:
		return "local5"
	case 22:
		return "local6"
	case 23:
		return "local7"
	default:
		return "unknown"
	}
}

func (sm SyslogMessage) Severity() SyslogMessageSeverity {
	s := sm.Priority & 7
	return SyslogMessageSeverity(s)
}

func (sm SyslogMessage) Facility() SyslogMessageFacility {
	f := sm.Priority >> 3
	return SyslogMessageFacility(f)
}

func parseSyslog(text string) (SyslogMessage, error) {
	sm := SyslogMessage{}

	r := regexp.MustCompile(`\<([0-9]{1,3})\>([A-Za-z]{1,3}.*[0-9]{1,2})[ ]{1}([A-Za-z0-9-_]+)[ ]{1}([A-Za-z0-9-_\[\]]+)[:]{1}(.*)`)
	m := r.FindAllStringSubmatch(text, -1)

	if len(m) < 1 {
		return sm, errors.New(fmt.Sprintf("unable to parse ('%s')", text))
	}

	if len(m[0]) < 5 {
		return sm, errors.New(fmt.Sprintf("unable to parse ('%s')", text))
	}

	pri, err := strconv.Atoi(m[0][1])
	if err != nil {
		pri = 0
	}

	ts, err := time.Parse(time.Stamp, m[0][2])
	now := time.Now()
	if err != nil {
		ts = now
	}

	sm.Priority = pri
	sm.Timestamp = time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), now.Nanosecond(), now.Location())
	sm.Host = m[0][3]
	sm.Application = m[0][4]
	sm.Message = strings.Trim(m[0][5], " ")

	return sm, nil
}

func main() {
	log.Printf("%s", version())
	log.Printf("listening on tcp://0.0.0.0:%d for HTTP\n", HTTP_PORT)
	go func() {
		hsrv := httpServer(HTTP_PORT)
		log.Fatalln(hsrv.ListenAndServe())
	}()

	log.Printf("listening on udp://0.0.0.0:%d for SYSLOG\n", SYSLOG_PORT)
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: SYSLOG_PORT, Zone: ""})
	if err != nil {
		log.Fatalln(err)
	}
	defer srv.Close()

	buffer := make([]byte, 1024)
	for {
		n, a, err := srv.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
		}

		p := strings.Split(a.String(), ":")
		var src string
		if len(p) > 1 {
			src = p[0]
		} else {
			src = a.String()
		}

		b := string(buffer[:n])
		m, err := parseSyslog(b)
		if err != nil {
			TOTAL_FAILS.Inc()
			log.Println(err)
			continue
		}

		m.Source = src

		log.Printf("%s:%d:%s(%d):%s(%d):%s:%s:%s:\"%s\"\n", m.Timestamp.Format("2006-01-02 15:04:05"), m.Priority, m.Severity(), m.Severity(), m.Facility(), m.Facility(), m.Source, m.Host, m.Application, m.Message)

		if _, ok := SOURCE_COUNT[src]; !ok {
			SOURCE_COUNT[src] = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_source_count", Help: "Messages processed"}, []string{"source", "host", "app", "severity", "facility"})
			SOURCE_BYTES[src] = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_source_bytes", Help: "Bytes processed"}, []string{"source", "host", "app", "severity", "facility"})
			REGISTRY.Register(SOURCE_COUNT[src])
			REGISTRY.Register(SOURCE_BYTES[src])
		}
		SOURCE_COUNT[src].With(prometheus.Labels{"source": src, "host": m.Host, "app": m.Application, "facility": m.Facility().String(), "severity": m.Severity().String()}).Inc()
		SOURCE_BYTES[src].With(prometheus.Labels{"source": src, "host": m.Host, "app": m.Application, "facility": m.Facility().String(), "severity": m.Severity().String()}).Add(float64(n))

		TOTAL_COUNT.With(prometheus.Labels{"app": m.Application, "facility": m.Facility().String(), "severity": m.Severity().String()}).Inc()
		TOTAL_BYTES.With(prometheus.Labels{"app": m.Application, "facility": m.Facility().String(), "severity": m.Severity().String()}).Add(float64(n))

		BUFFER.Value = m
		BUFFER = BUFFER.Next()
	}

	log.Printf("exiting\n")
	os.Exit(0)
}
