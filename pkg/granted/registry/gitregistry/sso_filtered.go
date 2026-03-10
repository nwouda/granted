package gitregistry

import (
	"context"
	"os"
	"path"
	"path/filepath"

	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

// SSOFilteredRegistry wraps a git registry with SSO-based subfolder filtering.
// It clones the repository and only syncs subfolders that match customer names
// extracted from the user's available SSO roles.
type SSOFilteredRegistry struct {
	*Registry
	ssoFilter       *grantedConfig.SSOFolderFilter
	customerFolders []string // populated after GetCustomerFolders is called
}

// SSOFilteredOpts contains options for creating an SSO-filtered git registry.
type SSOFilteredOpts struct {
	Opts
	SSOFilter *grantedConfig.SSOFolderFilter
}

// NewSSOFiltered creates a new SSO-filtered git registry.
// The registry will enumerate subfolders in the repository and sync only those
// that match customer names extracted from SSO roles.
func NewSSOFiltered(opts SSOFilteredOpts) (*SSOFilteredRegistry, error) {
	reg, err := New(opts.Opts)
	if err != nil {
		return nil, err
	}

	return &SSOFilteredRegistry{
		Registry:  reg,
		ssoFilter: opts.SSOFilter,
	}, nil
}

// SetCustomerFolders sets the list of customer folders to sync.
// This is called from the registry package after fetching SSO roles.
func (r *SSOFilteredRegistry) SetCustomerFolders(folders []string) {
	r.customerFolders = folders
}

// GetRepoPath returns the path to the cloned repository.
func (r *SSOFilteredRegistry) GetRepoPath() string {
	return r.clonedTo
}

// Pull ensures the repository is cloned and up-to-date.
func (r *SSOFilteredRegistry) Pull() error {
	return r.pull()
}

// EnumerateSubfolders lists all immediate subfolders in the repository root
// (or in the configured Path if set) that contain a granted.yml file.
func (r *SSOFilteredRegistry) EnumerateSubfolders() ([]string, error) {
	baseDir := r.clonedTo
	if r.opts.Path != "" {
		baseDir = path.Join(r.clonedTo, r.opts.Path)
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	filename := "granted.yml"
	if r.opts.Filename != "" {
		filename = r.opts.Filename
	}

	var subfolders []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Skip hidden directories
		if entry.Name()[0] == '.' {
			continue
		}

		// Check if the subfolder contains a granted.yml file
		configPath := filepath.Join(baseDir, entry.Name(), filename)
		if _, err := os.Stat(configPath); err == nil {
			subfolders = append(subfolders, entry.Name())
			clio.Debugf("Found customer folder: %s", entry.Name())
		}
	}

	return subfolders, nil
}

// AWSProfiles returns AWS profiles from customer subfolders that match SSO roles.
// If no customer folders are set, it falls back to standard git registry behavior.
func (r *SSOFilteredRegistry) AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error) {
	err := r.pull()
	if err != nil {
		return nil, err
	}

	// If no SSO filtering or no customer folders set, fall back to standard behavior
	if r.ssoFilter == nil || len(r.customerFolders) == 0 {
		return r.Registry.AWSProfiles(ctx, interactive)
	}

	// Load profiles from each customer folder
	result := ini.Empty()

	for _, customerFolder := range r.customerFolders {
		profiles, err := r.loadCustomerProfiles(ctx, customerFolder, interactive)
		if err != nil {
			clio.Warnf("Failed to load profiles from customer folder '%s': %v", customerFolder, err)
			continue
		}

		// Merge profiles from this customer into the result
		for _, section := range profiles.Sections() {
			if section.Name() == "DEFAULT" {
				continue
			}
			newSection, err := result.NewSection(section.Name())
			if err != nil {
				// Section might already exist if there are duplicates
				existingSection := result.Section(section.Name())
				if existingSection != nil {
					newSection = existingSection
				} else {
					return nil, err
				}
			}
			for _, key := range section.Keys() {
				_, _ = newSection.NewKey(key.Name(), key.Value())
			}
		}
	}

	return result, nil
}

// loadCustomerProfiles loads AWS profiles from a specific customer folder.
func (r *SSOFilteredRegistry) loadCustomerProfiles(ctx context.Context, customerFolder string, interactive bool) (*ini.File, error) {
	baseDir := r.clonedTo
	if r.opts.Path != "" {
		baseDir = path.Join(r.clonedTo, r.opts.Path)
	}

	customerPath := path.Join(baseDir, customerFolder)

	filename := "granted.yml"
	if r.opts.Filename != "" {
		filename = r.opts.Filename
	}

	filepath := path.Join(customerPath, filename)
	clio.Debugf("Loading customer config from %s", filepath)

	// Read and parse the granted.yml from the customer folder
	file, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var cfg ConfigYAML
	if err := parseYAML(file, &cfg); err != nil {
		return nil, err
	}

	err = cfg.PromptRequiredKeys(r.opts.RequiredKeys, interactive, r.opts.Name)
	if err != nil {
		return nil, err
	}

	result := ini.Empty()
	for _, cfile := range cfg.AwsConfigPaths {
		awsConfigPath := path.Join(customerPath, cfile)
		clio.Debugf("Loading aws config file from %s", awsConfigPath)
		err := result.Append(awsConfigPath)
		if err != nil {
			return nil, err
		}
	}

	clio.Infof("Loaded %d profiles from customer '%s'", len(result.Sections())-1, customerFolder)
	return result, nil
}

// parseYAML is a helper to parse YAML content
func parseYAML(content []byte, cfg *ConfigYAML) error {
	return yaml.Unmarshal(content, cfg)
}
