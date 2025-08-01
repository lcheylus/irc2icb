// Package for outputs/logs with level Debug, Info and Error

package utils

import "log"

// Print log for level = DEBUG
func LogDebug(msg string) {
	log.Printf("[DEBUG] %s", msg)
}

// Print log for level = DEBUG with string format
func LogDebugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

// Print log for level = INFO
func LogInfo(msg string) {
	log.Printf("[INFO] %s", msg)
}

// Print log for level = INFO with string format
func LogInfof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// Print log for level = ERROR and exit
func LogError(msg string) {
	log.Fatalf("[ERROR] %s", msg)
}

// Print log for level = ERROR with string format, then exit
func LogErrorf(format string, args ...interface{}) {
	log.Fatalf("[ERROR] "+format, args...)
}
