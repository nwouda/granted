package registry

import (
	"context"
	"sort"

	"github.com/common-fate/clio"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/granted/registry/gitregistry"
	"gopkg.in/ini.v1"
)

type Registry interface {
	AWSProfiles(ctx context.Context, interactive bool) (*ini.File, error)
}

type loadedRegistry struct {
	Config   grantedConfig.Registry
	Registry Registry
}

func GetProfileRegistries(interactive bool) ([]loadedRegistry, error) {
	return GetProfileRegistriesWithContext(context.Background(), interactive)
}

func GetProfileRegistriesWithContext(ctx context.Context, interactive bool) ([]loadedRegistry, error) {
	gConf, err := grantedConfig.Load()
	if err != nil {
		return nil, err
	}

	if len(gConf.ProfileRegistry.Registries) == 0 {
		return []loadedRegistry{}, nil
	}

	var registries []loadedRegistry
	for _, r := range gConf.ProfileRegistry.Registries {

		if r.Type == "git" || r.Type == "" {
			// Check if this registry has SSO role filtering enabled
			if r.SSORoleFilter != nil && r.SSORoleFilter.SSOStartURL != "" {
				reg, err := createSSOFilteredRegistry(ctx, r, interactive)
				if err != nil {
					clio.Warnf("Failed to create SSO-filtered registry '%s': %v", r.Name, err)
					continue
				}
				registries = append(registries, loadedRegistry{
					Config:   r,
					Registry: reg,
				})
			} else {
				// Standard git registry
				reg, err := gitregistry.New(gitregistry.Opts{
					Name:        r.Name,
					URL:         r.URL,
					Path:        r.Path,
					Filename:    r.Filename,
					Ref:         r.Ref,
					Interactive: interactive,
				})

				if err != nil {
					return nil, err
				}
				registries = append(registries, loadedRegistry{
					Config:   r,
					Registry: reg,
				})
			}
		}
	}

	// this will sort the registry based on priority.
	sort.Slice(registries, func(i, j int) bool {
		a := registries[i].Config.Priority
		b := registries[j].Config.Priority

		return a > b
	})

	return registries, nil
}

// createSSOFilteredRegistry creates a git registry with SSO-based subfolder filtering.
func createSSOFilteredRegistry(ctx context.Context, r grantedConfig.Registry, interactive bool) (Registry, error) {
	reg, err := gitregistry.NewSSOFiltered(gitregistry.SSOFilteredOpts{
		Opts: gitregistry.Opts{
			Name:        r.Name,
			URL:         r.URL,
			Path:        r.Path,
			Filename:    r.Filename,
			Ref:         r.Ref,
			Interactive: interactive,
		},
		SSOFilter: r.SSORoleFilter,
	})
	if err != nil {
		return nil, err
	}

	// Pull the repository first so we can enumerate subfolders
	if err := reg.Pull(); err != nil {
		return nil, err
	}

	// Get available subfolders in the repository
	availableFolders, err := reg.EnumerateSubfolders()
	if err != nil {
		return nil, err
	}
	clio.Debugf("Available customer folders in repository: %v", availableFolders)

	// Get customer names from SSO roles
	customerNames, err := GetCustomerNamesFromSSORoles(ctx, r.SSORoleFilter, interactive)
	if err != nil {
		if IsSSOLoginRequiredError(err) {
			clio.Warnf("SSO login required for SSO role filtering on registry '%s'. Skipping SSO filtering.", r.Name)
			// Fall back to no filtering - return an empty registry that won't load any profiles
			return reg, nil
		}
		return nil, err
	}
	clio.Debugf("Customer names from SSO roles: %v", customerNames)

	// Match customer names to available folders (case-insensitive)
	matchedFolders := matchCustomerFolders(customerNames, availableFolders)
	clio.Infof("Matched %d customer folders from SSO roles for registry '%s': %v", len(matchedFolders), r.Name, matchedFolders)

	// Set the customer folders to sync
	reg.SetCustomerFolders(matchedFolders)

	return reg, nil
}

// matchCustomerFolders matches customer names from SSO roles to available folders.
// The matching is case-insensitive.
func matchCustomerFolders(customerNames []string, availableFolders []string) []string {
	// Create a map of lowercase folder names to original folder names
	folderMap := make(map[string]string)
	for _, folder := range availableFolders {
		folderMap[toLower(folder)] = folder
	}

	var matched []string
	for _, customer := range customerNames {
		if folder, ok := folderMap[toLower(customer)]; ok {
			matched = append(matched, folder)
		} else {
			clio.Debugf("Customer '%s' from SSO roles has no matching folder in repository", customer)
		}
	}

	return matched
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
