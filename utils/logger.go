// Package for outputs/logs with level Debug, Info and Error
// Inspired by Go stdlib slog package

package utils

import "log"

type Level int

const (
	LevelDebug Level = -4
	LevelInfo  Level = 0
	LevelWarn  Level = 4
	LevelError Level = 8
)

// Internal value for logs level
var logLevel Level

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
		log.Printf("[DEBUG] %s", msg)
	}
}

// Print log for level = DEBUG with string format
func LogDebugf(format string, args ...interface{}) {
	if getLevel() <= LevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// Print log for level = WARN
func LogWarn(msg string) {
	if getLevel() <= LevelWarn {
		log.Printf("[WARN] %s", msg)
	}
}

// Print log for level = WARN with string format
func LogWarnf(format string, args ...interface{}) {
	if getLevel() <= LevelWarn {
		log.Printf("[WARN] "+format, args...)
	}
}

// Print log for level = INFO
func LogInfo(msg string) {
	if getLevel() <= LevelInfo {
		log.Printf("[INFO] %s", msg)
	}
}

// Print log for level = INFO with string format
func LogInfof(format string, args ...interface{}) {
	if getLevel() <= LevelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

// Print log for level = ERROR and exit
func LogError(msg string) {
	log.Fatalf("[ERROR] %s", msg)
}

// Print log for level = ERROR with string format, then exit
func LogErrorf(format string, args ...interface{}) {
	log.Fatalf("[ERROR] "+format, args...)
}
