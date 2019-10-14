// This package provides some utility tooling for authorization to Azure resources.
// Many projects build a layer like this on top of the Azure SDKs to handle resource authorization.
// This package attempts to provide a single source for such a layer.
package azauth

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

// Config holds environment settings, cached authorizers, and global loggers.
// Notably, the environment settings contain the name of the Azure Cloud,
// required for parameterizing authentication for for each Cloud environment (e.g. Public, Fairfax, Mooncake).
type Config struct {
	userAgent string
	env       *azure.Environment
}

type Option func(*Config)

// New fetches and caches environment settings for resource authentication and initializes loggers.
func New(opts ...Option) (*Config, error) {
	var err error
	var settings auth.EnvironmentSettings

	if settings, err = auth.GetSettingsFromEnvironment(); err != nil {
		return nil, err
	}

	c := &Config{
		userAgent: "azauth",
		env:       &settings.Environment,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// UserAgent provides a method of setting the user agent on the client.
func UserAgent(userAgent string) Option {
	return func(c *Config) {
		c.userAgent = userAgent
	}
}

// AuthorizeClientForResource tries to fetch an authorizer using GetAuthorizerForResource and inject it into a client.
func (c *Config) AuthorizeClientForResource(client *autorest.Client, resource string) (err error) {
	if authorizer, err := auth.NewAuthorizerFromEnvironmentWithResource(resource); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClienet tries to fetch an authorizer for management operations.
func (c *Config) AuthorizeClient(client *autorest.Client) (err error) {
	if authorizer, err := auth.NewAuthorizerFromEnvironment(); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClientFromFile tries to fetch an authorizer using GetFileAuthorizer and inject it into a client.
func (c *Config) AuthorizeClientFromFile(client *autorest.Client) (err error) {
	if authorizer, err := auth.NewAuthorizerFromFile(c.env.ResourceManagerEndpoint); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClientFromFile tries to fetch an authorizer using GetFileAuthorizer and inject it into a client.
func (c *Config) AuthorizeClientFromFileForResource(client *autorest.Client, resource string) (err error) {
	if authorizer, err := auth.NewAuthorizerFromFileWithResource(resource); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}
