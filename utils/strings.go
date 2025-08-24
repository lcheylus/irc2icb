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

// Trim hostname for user for IP, format = [<ip>]
func TrimHostname(hostname string) string {
	return strings.Trim(hostname, "[]")
}

// SplitString splits the input string into multiple substrings of size max_size
// while ensuring the split happens at a space boundary.
func SplitString(input string, max_size int) []string {
	var result []string

	if len(input) <= max_size {
		return []string{input}
	}

	// Check if there are spaces in the string (to decide whether to split by space)
	if strings.Contains(input, " ") {
		// Split the content by space to preserve word boundaries
		words := strings.Fields(input)

		var currentSegment string

		for _, word := range words {
			// If adding this word exceeds maxInputSize, finalize the current segment
			if len(currentSegment)+len(word)+1 > max_size {
				// Add current segment to the result and reset
				result = append(result, currentSegment)
				currentSegment = word
			} else {
				// Otherwise, append the word to the current segment
				if currentSegment != "" {
					currentSegment += " "
				}
				currentSegment += word
			}
		}

		// Don't forget to append the last segment if there's any content left
		if currentSegment != "" {
			result = append(result, currentSegment)
		}
	} else {
		// If no spaces are found, split the input based on max_size
		for i := 0; i < len(input); i += max_size {
			end := i + max_size
			if end > len(input) {
				end = len(input)
			}
			result = append(result, input[i:end])
		}
	}

	return result
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
