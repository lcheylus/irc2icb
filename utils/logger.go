// Package for outputs/logs with level Debug, Info and Error
// Inspired by Go stdlib slog package

package utils

import (
	"fmt"
	"log"
)

type Level int

// color pallete map
// Code from https://github.com/Mandala/go-log/blob/master/colorful/colorful.go

// TODO Handle case with outputs in file => no color
var (
	colorOff    = []byte("\033[0m")
	colorRed    = []byte("\033[0;31m")
	colorGreen  = []byte("\033[0;32m")
	colorOrange = []byte("\033[0;33m")
	colorBlue   = []byte("\033[0;34m")
	colorPurple = []byte("\033[0;35m")
	colorCyan   = []byte("\033[0;36m")
	colorGray   = []byte("\033[0;37m")
)

const (
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
	colorGray = []byte("")
}

// Set logs level
func SetLogLevel(level Level) {
	logLevel = level
}

// Get logs level
func getLevel() Level {
	return logLevel
}

// Print log for level = DEBUG
func LogDebug(msg string) {
	if getLevel() <= LevelDebug {
		prefix := fmt.Sprintf("%sDEBUG%s", colorGreen, colorOff)
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = DEBUG with string format
func LogDebugf(format string, args ...interface{}) {
	if getLevel() <= LevelDebug {
		prefix := fmt.Sprintf("%sDEBUG%s", colorGreen, colorOff)
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = WARN
func LogWarn(msg string) {
	if getLevel() <= LevelWarn {
		prefix := fmt.Sprintf("%sWARN%s ", colorOrange, colorOff)
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = WARN with string format
func LogWarnf(format string, args ...interface{}) {
	if getLevel() <= LevelWarn {
		// log.Printf("[WARN] "+format, args...)
		prefix := fmt.Sprintf("%sWARN%s ", colorOrange, colorOff)
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = INFO
func LogInfo(msg string) {
	if getLevel() <= LevelInfo {
		prefix := fmt.Sprintf("%sINFO%s ", colorCyan, colorOff)
		log.Printf("%s %s", prefix, msg)
	}
}

// Print log for level = INFO with string format
func LogInfof(format string, args ...interface{}) {
	if getLevel() <= LevelInfo {
		// log.Printf("[INFO] "+format, args...)
		prefix := fmt.Sprintf("%sINFO%s ", colorCyan, colorOff)
		log.Printf(prefix+" "+format, args...)
	}
}

// Print log for level = ERROR
func LogError(msg string) {
	prefix := fmt.Sprintf("%sERROR%s", colorRed, colorOff)
	log.Printf("%s %s", prefix, msg)
}

// Print log for level = ERROR with string format
func LogErrorf(format string, args ...interface{}) {
	prefix := fmt.Sprintf("%sERROR%s", colorRed, colorOff)
	log.Printf(prefix+" "+format, args...)
}

// Print log for level = ERROR then exit
func LogFatal(msg string) {
	prefix := fmt.Sprintf("%sFATAL%s", colorPurple, colorOff)
	log.Fatalf("%s %s", prefix, msg)
}

// Print log for level = ERROR with string format
// Print log for level = ERROR then exit
func LogFatalf(format string, args ...interface{}) {
	prefix := fmt.Sprintf("%sFATAL%s", colorPurple, colorOff)
	log.Fatalf(prefix+" "+format, args...)
}
