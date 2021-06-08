package main

import (
	"fmt"
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

func (s SyslogMessageSeverity) String() string {
	switch s {
	case 0:
		return "emerg"
	case 1:
		return "alert"
	case 2:
		return "crit"
	case 3:
		return "error"
	case 4:
		return "warn"
	case 5:
		return "notice"
	case 6:
		return "info"
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

func (sm SyslogMessage) String() string {
	return fmt.Sprintf("%-19s %-7s %-11s %-15s %-30s %-12s \"%s\"", sm.Timestamp.Format("2006-01-02 15:04:05"), sm.Severity(), sm.Facility(), sm.Source, sm.Host, sm.Application, sm.Message)
}
