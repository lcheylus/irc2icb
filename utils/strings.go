// Package for strings manipulation with ICB/IRC protocols

package utils

import (
	"strings"
)

// Check if string is a valid IRC channel (starts with '#')
func IsValidIrcChannel(channel string) bool {
	if strings.HasPrefix(channel, "#") {
		return true
	}
	return false
}

// Convert string for ICB group's name to IRC channel
func GroupToChannel(group string) string {
	return "#" + group
}

// Convert string from IRC channel's name to ICB group
func GroupFromChannel(channel string) string {
	return channel[1:]
}
