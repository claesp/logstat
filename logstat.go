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
	if bs := os.Getenv("BUFFER_SIZE"); len(bs) > 0 {
		bsi, err := strconv.Atoi(bs)
		if err == nil {
			BUFFER_SIZE = bsi
		}
	}

	if hp := os.Getenv("HTTP_PORT"); len(hp) > 0 {
		hpi, err := strconv.Atoi(hp)
		if err == nil {
			HTTP_PORT = hpi
		}
	}

	if sp := os.Getenv("SYSLOG_PORT"); len(sp) > 0 {
		spi, err := strconv.Atoi(sp)
		if err == nil {
			SYSLOG_PORT = spi
		}
	}

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
	var filterBy, filterValue string
	p := strings.Split(req.RequestURI, "/")
	if len(p) == 3 || len(p) == 4 {
		filterBy = strings.ToLower(p[1])
		filterValue = strings.ToLower(p[2])
	}

	BUFFER.Do(func(p interface{}) {
		if p == nil {
			return
		}
		m := p.(SyslogMessage)

		switch filterBy {
		case "severity":
			if strings.ToLower(m.Severity().String()) != filterValue {
				return
			}
		case "facility":
			if strings.ToLower(m.Facility().String()) != filterValue {
				return
			}
		case "source":
			if strings.ToLower(m.Source) != filterValue {
				return
			}
		case "app":
			if strings.ToLower(m.Application) != filterValue {
				return
			}
		case "host":
			if strings.ToLower(m.Host) != filterValue {
				return
			}
		}

		fmt.Fprintf(res, "%s\n", m)
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

func parseSyslogSource(text string) string {
	var src string

	p := strings.Split(text, ":")
	if len(p) > 1 {
		src = p[0]
	}

	return src
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

	app := m[0][4]
	bPos := strings.Index(app, "[")
	if bPos > 0 {
		app = app[:bPos]
	}

	sm.Priority = pri
	sm.Timestamp = time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), now.Nanosecond(), now.Location())
	sm.Host = m[0][3]
	sm.Application = app
	sm.Message = strings.Trim(m[0][5], " ")

	return sm, nil
}

func main() {
	log.Printf("%s", version())
	log.Printf("BUFFER_SIZE is %d\n", BUFFER_SIZE)
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

		src := parseSyslogSource(a.String())

		b := string(buffer[:n])
		m, err := parseSyslog(b)
		if err != nil {
			TOTAL_FAILS.Inc()
			log.Println(err)
			continue
		}

		m.Source = src

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
}
