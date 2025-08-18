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

// Comparison function between 2 users' nick
// => sort by moderator status (starts with @)
func CompareUser(user1, user2 string) bool {
	if strings.HasPrefix(user1, "@") {
		return true
	}
	return false
}
