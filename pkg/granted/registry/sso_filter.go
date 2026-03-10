package registry

import (
	"context"
	"regexp"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	grantedConfig "github.com/fwdcloudsec/granted/pkg/config"
	"github.com/fwdcloudsec/granted/pkg/idclogin"
	"github.com/fwdcloudsec/granted/pkg/securestorage"
	"golang.org/x/sync/errgroup"
)

// GetCustomerNamesFromSSORoles fetches all available SSO roles and extracts customer names
// using the provided regex pattern. The first capture group in the pattern is used as the
// customer name.
func GetCustomerNamesFromSSORoles(ctx context.Context, ssoFilter *grantedConfig.SSOFolderFilter, interactive bool) ([]string, error) {
	if ssoFilter == nil {
		return nil, nil
	}

	roleNames, err := listSSORoleNames(ctx, ssoFilter, interactive)
	if err != nil {
		return nil, err
	}

	return extractCustomerNames(roleNames, ssoFilter.RolePattern)
}

// listSSORoleNames fetches all available SSO role names from the configured SSO instance.
func listSSORoleNames(ctx context.Context, ssoFilter *grantedConfig.SSOFolderFilter, interactive bool) ([]string, error) {
	region, err := expandRegion(ssoFilter.SSORegion)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryer(func() aws.Retryer {
		return retry.NewStandard(func(so *retry.StandardOptions) {
			so.RateLimiter = ratelimit.NewTokenRateLimit(100000)
			so.MaxAttempts = 15
		})
	}))
	if err != nil {
		return nil, err
	}
	cfg.Region = region

	accessToken, err := getSSOAccessToken(ctx, cfg, ssoFilter, interactive)
	if err != nil {
		return nil, err
	}

	ssoClient := sso.NewFromConfig(cfg)
	roleNames, err := fetchAllRoleNames(ctx, ssoClient, accessToken)
	if err != nil {
		return nil, err
	}

	return roleNames, nil
}

// getSSOAccessToken retrieves a valid SSO access token, prompting for login if needed.
func getSSOAccessToken(ctx context.Context, cfg aws.Config, ssoFilter *grantedConfig.SSOFolderFilter, interactive bool) (string, error) {
	secureSSOTokenStorage := securestorage.NewSecureSSOTokenStorage()
	ssoTokenFromSecureCache := secureSSOTokenStorage.GetValidSSOToken(ctx, ssoFilter.SSOStartURL)

	if ssoTokenFromSecureCache != nil {
		return ssoTokenFromSecureCache.AccessToken, nil
	}

	// Try to get from plaintext cache
	ssoTokenFromPlainText := cfaws.GetValidSSOTokenFromPlaintextCache(ssoFilter.SSOStartURL)
	if ssoTokenFromPlainText != nil {
		secureSSOTokenStorage.StoreSSOToken(ssoFilter.SSOStartURL, *ssoTokenFromPlainText)
		return ssoTokenFromPlainText.AccessToken, nil
	}

	// Need to login
	if !interactive {
		clio.Errorf("SSO login required for SSO role filtering. Run 'granted sso login --sso-start-url %s --sso-region %s' first.",
			ssoFilter.SSOStartURL, ssoFilter.SSORegion)
		return "", errSSOLoginRequired
	}

	newSSOToken, err := idclogin.Login(ctx, cfg, ssoFilter.SSOStartURL, ssoFilter.SSOScopes)
	if err != nil {
		return "", err
	}
	secureSSOTokenStorage.StoreSSOToken(ssoFilter.SSOStartURL, *newSSOToken)
	return newSSOToken.AccessToken, nil
}

// fetchAllRoleNames fetches all role names from all accounts accessible via SSO.
func fetchAllRoleNames(ctx context.Context, ssoClient *sso.Client, accessToken string) ([]string, error) {
	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	var roleNames []string

	listAccountsNextToken := ""
	for {
		listAccountsInput := sso.ListAccountsInput{
			AccessToken: &accessToken,
		}
		if listAccountsNextToken != "" {
			listAccountsInput.NextToken = &listAccountsNextToken
		}

		listAccountsOutput, err := ssoClient.ListAccounts(ctx, &listAccountsInput)
		if err != nil {
			return nil, err
		}

		for _, accountLoop := range listAccountsOutput.AccountList {
			account := accountLoop
			g.Go(func() error {
				listAccountRolesNextToken := ""
				for {
					listAccountRolesInput := sso.ListAccountRolesInput{
						AccessToken: &accessToken,
						AccountId:   account.AccountId,
					}
					if listAccountRolesNextToken != "" {
						listAccountRolesInput.NextToken = &listAccountRolesNextToken
					}

					listAccountRolesOutput, err := ssoClient.ListAccountRoles(gctx, &listAccountRolesInput)
					if err != nil {
						return err
					}

					mu.Lock()
					for _, role := range listAccountRolesOutput.RoleList {
						roleNames = append(roleNames, *role.RoleName)
					}
					mu.Unlock()

					if listAccountRolesOutput.NextToken == nil {
						break
					}
					listAccountRolesNextToken = *listAccountRolesOutput.NextToken
				}
				return nil
			})
		}

		if listAccountsOutput.NextToken == nil {
			break
		}
		listAccountsNextToken = *listAccountsOutput.NextToken
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, name := range roleNames {
		if !seen[name] {
			seen[name] = true
			unique = append(unique, name)
		}
	}

	return unique, nil
}

// extractCustomerNames applies the regex pattern to each role name and extracts the customer name
// from the first capture group.
func extractCustomerNames(roleNames []string, pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var customers []string

	for _, roleName := range roleNames {
		matches := re.FindStringSubmatch(roleName)
		if len(matches) >= 2 {
			customer := matches[1]
			if customer != "" && !seen[customer] {
				seen[customer] = true
				customers = append(customers, customer)
				clio.Debugf("Extracted customer '%s' from SSO role '%s'", customer, roleName)
			}
		}
	}

	clio.Infof("Found %d customers from SSO roles matching pattern '%s'", len(customers), pattern)
	return customers, nil
}

// expandRegion expands region shortcodes to full region names if needed.
// Using cfaws.ExpandRegion for full region expansion.
func expandRegion(region string) (string, error) {
	return cfaws.ExpandRegion(region)
}

// errSSOLoginRequired is returned when SSO login is required but interactive mode is disabled.
var errSSOLoginRequired = &ssoLoginRequiredError{}

type ssoLoginRequiredError struct{}

func (e *ssoLoginRequiredError) Error() string {
	return "SSO login required for SSO role filtering"
}

// IsSSOLoginRequiredError checks if the error indicates SSO login is required.
func IsSSOLoginRequiredError(err error) bool {
	_, ok := err.(*ssoLoginRequiredError)
	return ok
}
