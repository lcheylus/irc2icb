// Package for strings manipulation with ICB/IRC protocols

package utils

import (
	"strings"
)

// Check if string is a valid IRC channel (starts with '#')
func IsValidChannel(channel string) bool {
	if strings.HasPrefix(channel, "#") {
		return true
	}
	return false
}

// Convert string for ICB group's name to IRC channel
func ToChannel(group string) string {
	return "#" + group
}

// Convert string from IRC channel's name to ICB group
func FromChannel(channel string) string {
	return channel[1:]
}
