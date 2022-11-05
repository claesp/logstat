package main

import (
	"container/ring"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	BUFFER       *ring.Ring
	BUFFER_SIZE  = 100000
	HTTP_PORT    = 8080
	MAJOR        = 0
	MINOR        = 0
	REGISTRY     *prometheus.Registry
	REVISION     = 20210603
	SOURCE_COUNT = make(map[string]*prometheus.CounterVec)
	SOURCE_BYTES = make(map[string]*prometheus.CounterVec)
	SYSLOG_PORT  = 60514
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

type Page struct {
	Title       string
	FilterBy    string
	FilterValue string
	Messages    []SyslogMessage
}

func httpRoot(res http.ResponseWriter, req *http.Request) {
	var filterBy, filterValue string
	p := strings.Split(req.RequestURI, "/")
	if len(p) == 3 || len(p) == 4 {
		filterBy = strings.ToLower(p[1])
		filterValue = strings.ToLower(p[2])
	}

	page := Page{}
	page.FilterBy = filterBy
	page.FilterValue = filterValue
	messages := make([]SyslogMessage, 0)
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
		case "year":
			if m.Timestamp.Format("2006") != filterValue {
				return
			}
		case "month":
			if m.Timestamp.Format("2006-01") != filterValue {
				return
			}
		case "day":
			if m.Timestamp.Format("2006-01-02") != filterValue {
				return
			}
		case "hour":
			if m.Timestamp.Format("2006-01-02t15") != filterValue {
				return
			}
		case "minute":
			if m.Timestamp.Format("2006-01-02t15:04") != filterValue {
				return
			}
		case "time":
			if m.Timestamp.Format("2006-01-02t15:04:05") != filterValue {
				return
			}
		}

		var prevTime time.Time
		if len(messages) > 0 {
			prev := messages[len(messages)-1]
			prevTime = prev.Timestamp
		} else {
			prevTime = m.Timestamp
		}
		m.Diff = m.Timestamp.Sub(prevTime).Truncate(time.Millisecond)

		messages = append(messages, m)
	})

	page.Title = fmt.Sprintf("logstat (%d/%d)", len(messages), BUFFER_SIZE)
	page.Messages = messages

	t, err := template.New("root").Parse(`{{define "logs"}}<!DOCTYPE html><html><head><meta charset="utf-8"><title>{{.Title}}</title><style type="text/css">body {font-family: monospace; margin: 1rem; padding: 0;} table {border-collapse: collapse;} td:nth-child(2), td:nth-child(3), td:nth-child(4), td:nth-child(5), td:nth-child(6), td:nth-child(7), td:nth-child(8) {padding-left: 1em;} td:nth-child(2) {text-align: right;} td {white-space: nowrap;} a {text-decoration: none; color: grey;} a:hover {color: white; background-color: blue;}</style></head><body><table><tbody>{{range .Messages}}<tr><td><a href="/year/{{.Timestamp.Format "2006"}}/" title="Filter by year '{{.Timestamp.Format "2006"}}'">{{.Timestamp.Format "2006"}}</a>-<a href="/month/{{.Timestamp.Format "2006-01"}}/" title="Filter by month '{{.Timestamp.Format "2006-01"}}'">{{.Timestamp.Format "01"}}</a>-<a href="/day/{{.Timestamp.Format "2006-01-02"}}/" title="Filter by day '{{.Timestamp.Format "2006-01-02"}}'">{{.Timestamp.Format "02"}}</a> <a href="/hour/{{.Timestamp.Format "2006-01-02T15"}}/" title="Filter by hour '{{.Timestamp.Format "2006-01-02 15"}}'">{{.Timestamp.Format "15"}}</a>:<a href="/minute/{{.Timestamp.Format "2006-01-02T15:04"}}/" title="Filter by minute '{{.Timestamp.Format "2006-01-02 15:04"}}'">{{.Timestamp.Format "04"}}</a>:<a href="/time/{{.Timestamp.Format "2006-01-02T15:04:05"}}/" title="Filter by second '{{.Timestamp.Format "2006-01-02 15:04:05"}}'">{{.Timestamp.Format "05.000"}}</a></td><td>{{.Diff}}</td><td><a href="/severity/{{.Severity}}/" title="Filter by severity '{{.Severity}}'">{{.Severity}}</a></td><td><a href="/facility/{{.Facility}}/" title="Filter by facility '{{.Facility}}'">{{.Facility}}</a></td><td><a href="/source/{{.Source}}/" title="Filter by source '{{.Source}}'">{{.Source}}</a></td><td><a href="/host/{{.Host}}/" title="Filter by host '{{.Host}}'">{{.Host}}</a></td><td><a href="/app/{{.Application}}/" title="Filter by application '{{.Application}}'">{{.Application}}</a></td><td>{{.Message}}</td></tr>{{end}}</tbody></table></body></html>{{end}}`)
	err = t.ExecuteTemplate(res, "logs", page)
	if err != nil {
		fmt.Fprintf(res, "%v", err)
	}
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

	/*conn, err := kafka.DialLeader(context.Background(), "tcp", "127.0.0.1:9092", "gcse-prod-syslog-raw", 0)
	if err != nil {
		log.Println("failed to dial leader:", err)
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))*/

	buffer := make([]byte, 1024)
	for {
		n, a, err := srv.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
		}

		src := parseSyslogSource(a.String())

		b := string(buffer[:n])
		m, err := ParseSyslog(b)
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

		/* _, err = conn.WriteMessages(kafka.Message{Value: []byte(b)})
		if err != nil {
			log.Println("failed to write messages:", err)
		} */
	}

	/* if err := conn.Close(); err != nil {
		log.Fatal("failed to close writer:", err)
	} */

	log.Printf("exiting\n")
}
