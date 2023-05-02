/*
 * wgvpn client - Copyright (C) 2023-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package logger

import (
	//"encoding/json"
	"fmt"
	"log"
	"runtime"

	"github.com/getsentry/sentry-go"
)

const (
	LOG_EMERG   = 0 /* system is unusable */
	LOG_ALERT   = 1 /* action must be taken immediately */
	LOG_CRIT    = 2 /* critical conditions */
	LOG_ERR     = 3 /* error conditions */
	LOG_WARNING = 4 /* warning conditions */
	LOG_NOTICE  = 5 /* normal but significant condition */
	LOG_INFO    = 6 /* informational */
	LOG_DEBUG   = 7 /* debug-level messages */
)

var name map[uint8]string = map[uint8]string{
	LOG_EMERG:   "EMERG",
	LOG_ALERT:   "ALERT",
	LOG_CRIT:    "CRIT",
	LOG_ERR:     "ERR",
	LOG_WARNING: "WARNING",
	LOG_NOTICE:  "NOTICE",
	LOG_INFO:    "INFO",
	LOG_DEBUG:   "DEBUG",
}

type Logger struct {
	Level  uint8
	sentry bool
}

func NewLogger(dsn string) *Logger {
	if dsn != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn: dsn,
			// Set TracesSampleRate to 1.0 to capture 100%
			// of transactions for performance monitoring.
			// We recommend adjusting this value in production,
			TracesSampleRate: 1.0,
		})

		if err != nil {
			log.Fatalf("sentry.Init: %s", err)
		}
	}

	return &Logger{Level: LOG_DEBUG, sentry: dsn != ""}
}

func (l *Logger) log(level uint8, facility string, entry ...interface{}) {

	if l == nil {
		return
	}

	if level <= l.Level {
		n := name[level]
		var a []interface{}
		a = append(a, n)
		a = append(a, facility)
		a = append(a, entry...)
		log.Println(a...)

		_, file, line, _ := runtime.Caller(2)
		a = append(a, fmt.Sprintf("%s:%d", file, line))

		//js, err := json.MarshalIndent(&a, "", " ")
		//if err != nil {
		if l.sentry {
			sentry.CaptureMessage(fmt.Sprintln(a...))
		}
		//} else {
		//	sentry.CaptureMessage(string(js))
		//}

		if level == LOG_EMERG {
			log.Fatal(a...)
		}
	}
}
func (l *Logger) Fatal(e ...interface{}) { l.log(LOG_EMERG, "fatal", e...) }

func (l *Logger) EMERG(f string, e ...interface{})   { l.log(LOG_EMERG, f, e...) }
func (l *Logger) ALERT(f string, e ...interface{})   { l.log(LOG_ALERT, f, e...) }
func (l *Logger) CRIT(f string, e ...interface{})    { l.log(LOG_CRIT, f, e...) }
func (l *Logger) ERR(f string, e ...interface{})     { l.log(LOG_ERR, f, e...) }
func (l *Logger) WARNING(f string, e ...interface{}) { l.log(LOG_WARNING, f, e...) }
func (l *Logger) NOTICE(f string, e ...interface{})  { l.log(LOG_NOTICE, f, e...) }
func (l *Logger) INFO(f string, e ...interface{})    { l.log(LOG_INFO, f, e...) }
func (l *Logger) DEBUG(f string, e ...interface{})   { l.log(LOG_DEBUG, f, e...) }
