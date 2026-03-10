package gitregistry

import (
	"os"
	"path/filepath"
	"testing"

	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSSOFiltered(t *testing.T) {
	tests := []struct {
		name      string
		opts      SSOFilteredOpts
		wantError bool
	}{
		{
			name: "creates registry with SSO filter",
			opts: SSOFilteredOpts{
				Opts: Opts{
					Name:     "test-registry",
					URL:      "https://github.com/test/repo.git",
					Filename: "granted.yml",
				},
				SSOFilter: &grantedConfig.SSOFolderFilter{
					SSOStartURL: "https://example.awsapps.com/start",
					SSORegion:   "us-east-1",
					RolePattern: `^Support(.+)$`,
				},
			},
			wantError: false,
		},
		{
			name: "creates registry without SSO filter",
			opts: SSOFilteredOpts{
				Opts: Opts{
					Name:     "test-registry",
					URL:      "https://github.com/test/repo.git",
					Filename: "granted.yml",
				},
				SSOFilter: nil,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, err := NewSSOFiltered(tt.opts)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, reg)
			}
		})
	}
}

func TestSSOFilteredRegistry_SetCustomerFolders(t *testing.T) {
	reg, err := NewSSOFiltered(SSOFilteredOpts{
		Opts: Opts{
			Name: "test-registry",
			URL:  "https://github.com/test/repo.git",
		},
	})
	require.NoError(t, err)

	// Set customer folders
	folders := []string{"Google", "Amazon", "Microsoft"}
	reg.SetCustomerFolders(folders)

	// Verify they were set
	assert.Equal(t, folders, reg.customerFolders)
}

func TestSSOFilteredRegistry_EnumerateSubfolders(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "sso-filter-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create subfolders with granted.yml
	for _, customer := range []string{"Google", "Amazon", "Microsoft"} {
		customerDir := filepath.Join(tmpDir, customer)
		err := os.Mkdir(customerDir, 0755)
		require.NoError(t, err)

		// Create granted.yml in each folder
		grantedYml := filepath.Join(customerDir, "granted.yml")
		err = os.WriteFile(grantedYml, []byte("awsConfig:\n  - config\n"), 0644)
		require.NoError(t, err)
	}

	// Create a folder without granted.yml
	noConfigDir := filepath.Join(tmpDir, "NoConfig")
	err = os.Mkdir(noConfigDir, 0755)
	require.NoError(t, err)

	// Create a hidden folder (should be skipped)
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	err = os.Mkdir(hiddenDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(hiddenDir, "granted.yml"), []byte(""), 0644)
	require.NoError(t, err)

	// Create a regular file (not a directory)
	err = os.WriteFile(filepath.Join(tmpDir, "regular-file.txt"), []byte(""), 0644)
	require.NoError(t, err)

	reg := &SSOFilteredRegistry{
		Registry: &Registry{
			clonedTo: tmpDir,
			opts:     Opts{},
		},
	}

	subfolders, err := reg.EnumerateSubfolders()
	require.NoError(t, err)

	// Should find Google, Amazon, Microsoft but not NoConfig, .hidden, or regular-file.txt
	assert.Len(t, subfolders, 3)
	assert.Contains(t, subfolders, "Google")
	assert.Contains(t, subfolders, "Amazon")
	assert.Contains(t, subfolders, "Microsoft")
	assert.NotContains(t, subfolders, "NoConfig")
	assert.NotContains(t, subfolders, ".hidden")
}

func TestSSOFilteredRegistry_EnumerateSubfolders_WithPath(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "sso-filter-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory path
	subPath := filepath.Join(tmpDir, "customers")
	err = os.Mkdir(subPath, 0755)
	require.NoError(t, err)

	// Create customer folders in the subdirectory
	customerDir := filepath.Join(subPath, "Google")
	err = os.Mkdir(customerDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(customerDir, "granted.yml"), []byte("awsConfig:\n  - config\n"), 0644)
	require.NoError(t, err)

	reg := &SSOFilteredRegistry{
		Registry: &Registry{
			clonedTo: tmpDir,
			opts: Opts{
				Path: "customers",
			},
		},
	}

	subfolders, err := reg.EnumerateSubfolders()
	require.NoError(t, err)

	assert.Len(t, subfolders, 1)
	assert.Contains(t, subfolders, "Google")
}

func TestSSOFilteredRegistry_EnumerateSubfolders_CustomFilename(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "sso-filter-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a customer folder with custom filename
	customerDir := filepath.Join(tmpDir, "Google")
	err = os.Mkdir(customerDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(customerDir, "custom-config.yml"), []byte("awsConfig:\n  - config\n"), 0644)
	require.NoError(t, err)

	// Create another folder with the default granted.yml (should not match)
	anotherDir := filepath.Join(tmpDir, "Amazon")
	err = os.Mkdir(anotherDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(anotherDir, "granted.yml"), []byte("awsConfig:\n  - config\n"), 0644)
	require.NoError(t, err)

	reg := &SSOFilteredRegistry{
		Registry: &Registry{
			clonedTo: tmpDir,
			opts: Opts{
				Filename: "custom-config.yml",
			},
		},
	}

	subfolders, err := reg.EnumerateSubfolders()
	require.NoError(t, err)

	// Should only find Google (has custom-config.yml), not Amazon (has granted.yml)
	assert.Len(t, subfolders, 1)
	assert.Contains(t, subfolders, "Google")
}
