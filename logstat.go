package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
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
	MAJOR        = 0
	MINOR        = 0
	REVISION     = 20210603
	SYSLOG_PORT  = 1514
	HTTP_PORT    = 8080
	SOURCE_COUNT = make(map[string]*prometheus.CounterVec)
	SOURCE_BYTES = make(map[string]*prometheus.CounterVec)
	TOTAL_COUNT  = promauto.NewCounter(prometheus.CounterOpts{Name: "logstat_count_total", Help: "Total messages processed"})
	TOTAL_BYTES  = promauto.NewCounter(prometheus.CounterOpts{Name: "logstat_bytes_total", Help: "Total bytes processed"})
	TOTAL_FAILS  = promauto.NewCounter(prometheus.CounterOpts{Name: "logstat_fails_total", Help: "Total failed messages"})
)

func version() string {
	return fmt.Sprintf("logstat %d.%d.%d\n", MAJOR, MINOR, REVISION)
}

func httpRoot(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(res, "%s", version())
}

func httpServer(port int) *http.Server {
	m := http.NewServeMux()

	m.Handle("/metrics", promhttp.Handler())
	m.HandleFunc("/", httpRoot)

	s := http.Server{
		Addr:    fmt.Sprintf(":%v", port),
		Handler: m,
	}

	return &s
}

type SyslogMessage struct {
	Severity    int
	Facility    int
	Timestamp   time.Time
	Host        string
	Application string
	Message     string
}

func parseSyslog(text string) (SyslogMessage, error) {
	sm := SyslogMessage{}

	r := regexp.MustCompile(`\<([0-9]{1,3})\>([A-Za-z]{1,3}.*[0-9]{1,2})[ ]{1}([A-Za-z0-9-_]+)[ ]{1}([A-Za-z0-9]+)[:]{1}(.*)`)
	m := r.FindAllStringSubmatch(text, -1)

	if len(m) < 1 {
		return sm, errors.New("unable to parse")
	}

	if len(m[0]) < 5 {
		return sm, errors.New("unable to parse")
	}

	/*sm.Severity = m[0][1]
	sm.Facility = m[0][1]
	sm.Timestamp = m[0][2]*/
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
		n, addr, err := srv.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
		}

		p := strings.Split(addr.String(), ":")
		var src string
		if len(p) > 1 {
			src = p[0]
		} else {
			src = addr.String()
		}

		b := string(buffer[:n])
		msg, err := parseSyslog(b)
		if err != nil {
			TOTAL_FAILS.Inc()
			log.Println(err)
			continue
		}

		log.Printf("%s:%d:%d:%s:%s:%s:\"%s\"\n", msg.Timestamp, msg.Severity, msg.Facility, src, msg.Host, msg.Application, msg.Message)

		if _, ok := SOURCE_COUNT[src]; !ok {
			SOURCE_COUNT[src] = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_source_count", Help: "Messages processed"}, []string{"source", "host", "app"})
			SOURCE_BYTES[src] = promauto.NewCounterVec(prometheus.CounterOpts{Name: "logstat_source_bytes", Help: "Bytes processed"}, []string{"source", "host", "app"})
		}
		SOURCE_COUNT[src].With(prometheus.Labels{"source": src, "host": msg.Host, "app": msg.Application}).Inc()
		SOURCE_BYTES[src].With(prometheus.Labels{"source": src, "host": msg.Host, "app": msg.Application}).Add(float64(n))

		TOTAL_COUNT.Inc()
		TOTAL_BYTES.Add(float64(n))
	}

	log.Printf("exiting\n")
	os.Exit(0)
}
