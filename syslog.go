package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SyslogMessage struct {
	Priority    int
	Timestamp   time.Time
	Host        string
	Application string
	Message     string
	Source      string
}

type SyslogMessageSeverity int

const (
	SyslogMessageSeverityEmergency SyslogMessageSeverity = iota
	SyslogMessageSeverityAlert     SyslogMessageSeverity = iota
	SyslogMessageSeverityCritical  SyslogMessageSeverity = iota
	SyslogMessageSeverityError     SyslogMessageSeverity = iota
	SyslogMessageSeverityWarning   SyslogMessageSeverity = iota
	SyslogMessageSeverityNotice    SyslogMessageSeverity = iota
	SyslogMessageSeverityInfo      SyslogMessageSeverity = iota
	SyslogMessageSeverityDebug     SyslogMessageSeverity = iota
)

func (s SyslogMessageSeverity) String() string {
	switch s {
	case SyslogMessageSeverityEmergency:
		return "emerg"
	case SyslogMessageSeverityAlert:
		return "alert"
	case SyslogMessageSeverityCritical:
		return "crit"
	case SyslogMessageSeverityError:
		return "error"
	case SyslogMessageSeverityWarning:
		return "warn"
	case SyslogMessageSeverityNotice:
		return "notice"
	case SyslogMessageSeverityInfo:
		return "info"
	case SyslogMessageSeverityDebug:
		return "debug"
	default:
		return "unknown"
	}
}

type SyslogMessageFacility int

const (
	SyslogMessageFacilityKernel       SyslogMessageFacility = iota
	SyslogMessageFacilityUser         SyslogMessageFacility = iota
	SyslogMessageFacilityMail         SyslogMessageFacility = iota
	SyslogMessageFacilitySystem       SyslogMessageFacility = iota
	SyslogMessageFacilitySecurity     SyslogMessageFacility = iota
	SyslogMessageFacilityInternal     SyslogMessageFacility = iota
	SyslogMessageFacilityLineprinter  SyslogMessageFacility = iota
	SyslogMessageFacilityNetworkNews  SyslogMessageFacility = iota
	SyslogMessageFacilityUucp         SyslogMessageFacility = iota
	SyslogMessageFacilityClock        SyslogMessageFacility = iota
	SyslogMessageFacilitySecurityAuth SyslogMessageFacility = iota
	SyslogMessageFacilityFtp          SyslogMessageFacility = iota
	SyslogMessageFacilityNtp          SyslogMessageFacility = iota
	SyslogMessageFacilityLogAudit     SyslogMessageFacility = iota
	SyslogMessageFacilityLogAlert     SyslogMessageFacility = iota
	SyslogMessageFacilityClockDaemon  SyslogMessageFacility = iota
	SyslogMessageFacilityLocal0       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal1       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal2       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal3       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal4       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal5       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal6       SyslogMessageFacility = iota
	SyslogMessageFacilityLocal7       SyslogMessageFacility = iota
)

func (f SyslogMessageFacility) String() string {
	switch f {
	case SyslogMessageFacilityKernel:
		return "kernel"
	case SyslogMessageFacilityUser:
		return "user"
	case SyslogMessageFacilityMail:
		return "mail"
	case SyslogMessageFacilitySystem:
		return "system"
	case SyslogMessageFacilitySecurity:
		return "auth"
	case SyslogMessageFacilityInternal:
		return "internal"
	case SyslogMessageFacilityLineprinter:
		return "lpr"
	case SyslogMessageFacilityNetworkNews:
		return "news"
	case SyslogMessageFacilityUucp:
		return "uucp"
	case SyslogMessageFacilityClock:
		return "clock"
	case SyslogMessageFacilitySecurityAuth:
		return "auth-priv"
	case SyslogMessageFacilityFtp:
		return "ftp"
	case SyslogMessageFacilityNtp:
		return "ntp"
	case SyslogMessageFacilityLogAudit:
		return "logaudit"
	case SyslogMessageFacilityLogAlert:
		return "logalert"
	case SyslogMessageFacilityClockDaemon:
		return "clock"
	case SyslogMessageFacilityLocal0:
		return "local0"
	case SyslogMessageFacilityLocal1:
		return "local1"
	case SyslogMessageFacilityLocal2:
		return "local2"
	case SyslogMessageFacilityLocal3:
		return "local3"
	case SyslogMessageFacilityLocal4:
		return "local4"
	case SyslogMessageFacilityLocal5:
		return "local5"
	case SyslogMessageFacilityLocal6:
		return "local6"
	case SyslogMessageFacilityLocal7:
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

func (sm SyslogMessage) String() string {
	return fmt.Sprintf("%-19s %-7s %-13s %-15s %-30s %-12s \"%s\"", sm.Timestamp.Format("2006/01/02 15:04:05"), sm.Severity(), sm.Facility(), sm.Source, sm.Host, sm.Application, sm.Message)
}

func ParseSyslogSource(text string) string {
	var src string

	p := strings.Split(text, ":")
	if len(p) > 1 {
		src = p[0]
	}

	return src
}

func ParseSyslog(text string) (SyslogMessage, error) {
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
	bPos := strings.Index(app, "[") /* Removing PID in app name */
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
