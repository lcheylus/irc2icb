// Tests for utils/strings package

package utils

import "testing"

func TestIsValidIrcChannel(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"#foo", true},
		{"bar", false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := IsValidIrcChannel(test.input)

			if result != test.expected {
				t.Errorf("For input '%s', expected %v, but got %v", test.input, test.expected, result)
			}
		})
	}
}

func TestGroupToChannel(t *testing.T) {
	input := "foo"
	expected := "#foo"

	result := GroupToChannel(input)
	if result != expected {
		t.Errorf("For input '%s', expected %v, but got %v", input, expected, result)
	}
}

func TestGroupFromChannel(t *testing.T) {
	input := "#foo"
	expected := "foo"

	result := GroupFromChannel(input)
	if result != expected {
		t.Errorf("For input '%s', expected %v, but got %v", input, expected, result)
	}
}

func TestCompareUser(t *testing.T) {
	tests := []struct {
		user1    string
		user2    string
		expected bool
	}{
		{"foo", "bar", false},
		{"@foo", "bar", true},
		{"foo", "@bar", false},
		{"@foo", "@bar", true},
	}

	for _, test := range tests {
		t.Run(test.user1, func(t *testing.T) {
			result := CompareUser(test.user1, test.user2)

			if result != test.expected {
				t.Errorf("For input '%s, %s', expected %v, but got %v", test.user1, test.user2, test.expected, result)
			}
		})
	}
}

func TestSplitString(t *testing.T) {
	lore_ipsum := "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
		"Mauris scelerisque ac ligula in eleifend. Praesent nisi libero, posuere vel mollis sed, " +
		"accumsan id erat. Curabitur non sem consequat, cursus sem et, dictum metus."
	lore_ipsum_result := []string{"Lorem ipsum dolor sit amet, consectetur",
		"adipiscing elit. Mauris scelerisque ac",
		"ligula in eleifend. Praesent nisi",
		"libero, posuere vel mollis sed, accumsan",
		"id erat. Curabitur non sem consequat,",
		"cursus sem et, dictum metus."}

	tests := []struct {
		input    string
		max_size int
		expected []string
	}{
		{"abcdef", 3, []string{"abc", "def"}},
		{"abcdef", 4, []string{"abcd", "ef"}},
		{"abcdefghi", 3, []string{"abc", "def", "ghi"}},
		{"abcdefghi", 4, []string{"abcd", "efgh", "i"}},
		{"abc def ghi", 4, []string{"abc", "def", "ghi"}},
		{lore_ipsum, 40, lore_ipsum_result},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := SplitString(test.input, test.max_size)

			for i, r := range result {
				if r != test.expected[i] {
					t.Errorf("For input '%s' with max_size=%d, expected %q, but got %q",
						test.input, test.max_size, test.expected, result)
					break
				}
			}
		})
	}
}

func TestTransliterateUnicodeToASCII(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abcdef", "abcdef"},
		{"abcdéf", "abcdef"},
		{"abcdèf", "abcdef"},
		{"àbcdef", "abcdef"},
		{"àbcdéf", "abcdef"},
		{"ça", "ca"},
		{"où", "ou"},
		{"ôü", "ou"},
		{"æ", "ae"},
		{"œ", "oe"},
		{"straße", "strasse"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := TransliterateUnicodeToASCII(test.input)

			if result != test.expected {
				t.Errorf("For input '%s', expected %v, but got %v", test.input, test.expected, result)
			}
		})
	}
}
