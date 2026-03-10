package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCustomerNames(t *testing.T) {
	tests := []struct {
		name        string
		roleNames   []string
		pattern     string
		expected    []string
		expectError bool
	}{
		{
			name:      "extracts customer from Support prefix",
			roleNames: []string{"SupportGoogle", "SupportAmazon", "SupportMicrosoft"},
			pattern:   `^Support(.+)$`,
			expected:  []string{"Google", "Amazon", "Microsoft"},
		},
		{
			name:      "extracts customer from Admin suffix",
			roleNames: []string{"GoogleAdmin", "AmazonAdmin", "MicrosoftAdmin"},
			pattern:   `^(.+)Admin$`,
			expected:  []string{"Google", "Amazon", "Microsoft"},
		},
		{
			name:      "handles mixed roles with pattern matching",
			roleNames: []string{"SupportGoogle", "ReadOnly", "SupportAmazon", "AdminRole"},
			pattern:   `^Support(.+)$`,
			expected:  []string{"Google", "Amazon"},
		},
		{
			name:      "deduplicates extracted customer names",
			roleNames: []string{"SupportGoogle", "SupportAmazon", "SupportGoogle"},
			pattern:   `^Support(.+)$`,
			expected:  []string{"Google", "Amazon"},
		},
		{
			name:      "returns empty for no matches",
			roleNames: []string{"ReadOnly", "AdminRole", "Developer"},
			pattern:   `^Support(.+)$`,
			expected:  []string(nil),
		},
		{
			name:        "returns error for invalid regex",
			roleNames:   []string{"SupportGoogle"},
			pattern:     `^Support[(.+)$`,
			expectError: true,
		},
		{
			name:      "handles empty role names",
			roleNames: []string{},
			pattern:   `^Support(.+)$`,
			expected:  []string(nil),
		},
		{
			name:      "handles complex pattern with multiple groups",
			roleNames: []string{"Customer-Google-Support", "Customer-Amazon-Support"},
			pattern:   `^Customer-(.+)-Support$`,
			expected:  []string{"Google", "Amazon"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractCustomerNames(tt.roleNames, tt.pattern)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestMatchCustomerFolders(t *testing.T) {
	tests := []struct {
		name             string
		customerNames    []string
		availableFolders []string
		expected         []string
	}{
		{
			name:             "matches exact case",
			customerNames:    []string{"Google", "Amazon"},
			availableFolders: []string{"Google", "Amazon", "Microsoft"},
			expected:         []string{"Google", "Amazon"},
		},
		{
			name:             "matches case insensitive",
			customerNames:    []string{"google", "AMAZON"},
			availableFolders: []string{"Google", "Amazon", "Microsoft"},
			expected:         []string{"Google", "Amazon"},
		},
		{
			name:             "returns empty for no matches",
			customerNames:    []string{"Apple", "Samsung"},
			availableFolders: []string{"Google", "Amazon", "Microsoft"},
			expected:         []string(nil),
		},
		{
			name:             "handles empty customer names",
			customerNames:    []string{},
			availableFolders: []string{"Google", "Amazon"},
			expected:         []string(nil),
		},
		{
			name:             "handles empty available folders",
			customerNames:    []string{"Google", "Amazon"},
			availableFolders: []string{},
			expected:         []string(nil),
		},
		{
			name:             "preserves original folder name case",
			customerNames:    []string{"GOOGLE", "amazon"},
			availableFolders: []string{"GoOgLe", "AmAzOn"},
			expected:         []string{"GoOgLe", "AmAzOn"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchCustomerFolders(tt.customerNames, tt.availableFolders)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello", "hello"},
		{"UPPERCASE", "uppercase"},
		{"lowercase", "lowercase"},
		{"MiXeD CaSe", "mixed case"},
		{"", ""},
		{"123ABC", "123abc"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toLower(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSSOLoginRequiredError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "is SSO login required error",
			err:      errSSOLoginRequired,
			expected: true,
		},
		{
			name:     "is not SSO login required error",
			err:      assert.AnError,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSSOLoginRequiredError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
