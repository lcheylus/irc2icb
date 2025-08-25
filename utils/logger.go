// Package for outputs/logs with levels Trace,  Debug, Info, Warn and Error
// Inspired by Go stdlib slog package

package utils

import (
	"fmt"
	"log"
	"runtime"
	"strings"
)

type Level int

// Color pallete map
// Code from https://github.com/Mandala/go-log/blob/master/colorful/colorful.go
var (
	colorOff    = []byte("\033[0m")
	colorRed    = []byte("\033[0;31m")
	colorGreen  = []byte("\033[0;32m")
	colorOrange = []byte("\033[0;33m")
	colorBlue   = []byte("\033[0;34m")
	colorPurple = []byte("\033[0;35m")
	colorCyan   = []byte("\033[0;36m")
	colorWhite  = []byte("\033[0;37m")
)

const (
	LevelTrace Level = -8
	LevelDebug Level = -4
	LevelInfo  Level = 0
	LevelWarn  Level = 4
	LevelError Level = 8
)

// Internal value for logs level
var logLevel Level

// Disable colors for logs
func WithoutColors() {
	colorOff = []byte("")
	colorRed = []byte("")
	colorGreen = []byte("")
	colorOrange = []byte("")
	colorBlue = []byte("")
	colorPurple = []byte("")
	colorCyan = []byte("")
	colorWhite = []byte("")
}

// Get package name of the function's caller
// Return string as "[<name>]" with a fixed size of 6 chars (size of "[main]")
func getPackageName() string {
	// Get the caller's stack frame information (1 refers to the direct caller, 2 would be one level up)
	_, file, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}

	// Get the last segment of the file path
	// The package name is usually the last part of the file path
	segments := strings.Split(file, "/")
	// Second last segment is usually the package name
	name := segments[len(segments)-2]
	if strings.Contains(name, "irc2icb") {
		return "[main]"
	} else {
		return fmt.Sprintf("%6s", fmt.Sprintf("[%s]", name))
	}
}

// Set logs level
func SetLogLevel(level Level) {
	logLevel = level
}

// Get logs level
func getLevel() Level {
	return logLevel
}

// Print log for level = TRACE
func LogTrace(msg string) {
	if getLevel() <= LevelTrace {
		prefix := fmt.Sprintf("%sTRACE%s %s", colorWhite, colorOff, getPackageName())
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = TRACE with string format
func LogTracef(format string, args ...interface{}) {
	if getLevel() <= LevelTrace {
		prefix := fmt.Sprintf("%sTRACE%s %s", colorWhite, colorOff, getPackageName())
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = DEBUG
func LogDebug(msg string) {
	if getLevel() <= LevelDebug {
		prefix := fmt.Sprintf("%sDEBUG%s %s", colorGreen, colorOff, getPackageName())
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = DEBUG with string format
func LogDebugf(format string, args ...interface{}) {
	if getLevel() <= LevelDebug {
		prefix := fmt.Sprintf("%sDEBUG%s %s", colorGreen, colorOff, getPackageName())
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = WARN
func LogWarn(msg string) {
	if getLevel() <= LevelWarn {
		prefix := fmt.Sprintf("%sWARN%s  %s", colorOrange, colorOff, getPackageName())
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = WARN with string format
func LogWarnf(format string, args ...interface{}) {
	if getLevel() <= LevelWarn {
		prefix := fmt.Sprintf("%sWARN%s  %s", colorOrange, colorOff, getPackageName())
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = INFO
func LogInfo(msg string) {
	if getLevel() <= LevelInfo {
		prefix := fmt.Sprintf("%sINFO%s  %s", colorCyan, colorOff, getPackageName())
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = INFO with string format
func LogInfof(format string, args ...interface{}) {
	if getLevel() <= LevelInfo {
		prefix := fmt.Sprintf("%sINFO%s  %s", colorCyan, colorOff, getPackageName())
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = ERROR
func LogError(msg string) {
	prefix := fmt.Sprintf("%sERROR%s %s", colorRed, colorOff, getPackageName())
	log.Printf("%s %s", prefix, msg)
}

// Print log for level = ERROR with string format
func LogErrorf(format string, args ...interface{}) {
	prefix := fmt.Sprintf("%sERROR%s %s", colorRed, colorOff, getPackageName())
	log.Printf(prefix+" "+format, args...)
}

// Print log for level = ERROR then exit
func LogFatal(msg string) {
	prefix := fmt.Sprintf("%sFATAL%s %s", colorPurple, colorOff, getPackageName())
	log.Fatalf("%s %s", prefix, msg)
}

// Print log for level = ERROR with string format, then exit
func LogFatalf(format string, args ...interface{}) {
	prefix := fmt.Sprintf("%sFATAL%s %s", colorPurple, colorOff, getPackageName())
	log.Fatalf(prefix+" "+format, args...)
}
