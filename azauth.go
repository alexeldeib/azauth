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

// GetAuthorizer returns a resource management authorizer for the current Azure Cloud environment.
func (c *Config) GetAuthorizer() (autorest.Authorizer, error) {
	return auth.NewAuthorizerFromEnvironment()
}

// GetAuthorizerForResource will return an authorizer to the resource or an error.
func (c *Config) GetAuthorizerForResource(resource string) (autorest.Authorizer, error) {
	return auth.NewAuthorizerFromEnvironmentWithResource(resource)
}

// GetFileAuthorizer returns a file-based resource management authorizer for the current Azure Cloud environment.
func (c *Config) GetFileAuthorizer() (autorest.Authorizer, error) {
	return auth.NewAuthorizerFromFile(c.env.ResourceManagerEndpoint)
}

// GetFileAuthorizerForResource will return a file-based authorizer to the resource or an error.
func (c *Config) GetFileAuthorizerForResource(resource string) (autorest.Authorizer, error) {
	return auth.NewAuthorizerFromFileWithResource(resource)
}

// AuthorizeClientForResource tries to fetch an authorizer using GetAuthorizerForResource and inject it into a client.
func (c *Config) AuthorizeClientForResource(client *autorest.Client, resource string) (err error) {
	if authorizer, err := c.GetAuthorizerForResource(resource); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClienet tries to fetch an authorizer for management operations.
func (c *Config) AuthorizeClient(client *autorest.Client) (err error) {
	if authorizer, err := c.GetAuthorizer(); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClientFromFile tries to fetch an authorizer using GetFileAuthorizer and inject it into a client.
func (c *Config) AuthorizeClientFromFile(client *autorest.Client) (err error) {
	if authorizer, err := c.GetFileAuthorizer(); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}

// AuthorizeClientFromFile tries to fetch an authorizer using GetFileAuthorizer and inject it into a client.
func (c *Config) AuthorizeClientFromFileForResource(client *autorest.Client, resource string) (err error) {
	if authorizer, err := c.GetFileAuthorizerForResource(resource); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(c.userAgent)
	}
	return
}
