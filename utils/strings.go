// Package for strings manipulation with ICB/IRC protocols

package utils

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
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

// Custom map for specific case of conversion from Unicode to ASCII string
var translateAsciiMap = map[rune]string{
	'ß': "ss",
	'ø': "o",
	'Ø': "O",
	'æ': "ae",
	'Æ': "AE",
	'œ': "oe",
	'Œ': "OE",
}

// TransliterateUnicodeToASCII converts a Unicode string to pure ASCII
// Diacritics marks are skipped and some chars are translated via a custom map.
func TransliterateUnicodeToASCII(input string) string {
	// Normalize the string to decomposed form (NFD)
	normStr := norm.NFD.String(input)
	result := make([]rune, 0, len(normStr))

	for _, r := range normStr {
		// Not a standard ASCII character
		if r > 127 {
			// Skip diacritics
			if unicode.Is(unicode.Mn, r) {
				continue
			}
			if repl, ok := translateAsciiMap[r]; ok {
				for _, replRune := range repl {
					result = append(result, replRune)
				}
			}
			// For non latin char, replace by *
			if !unicode.Is(unicode.Latin, r) {
				result = append(result, rune('*'))
			}
			continue
		}
		result = append(result, r)
	}

	return string(result)
}
