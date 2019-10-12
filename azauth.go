// This package provides some utility tooling for authorization to Azure resources.
// Many projects build a layer like this on top of the Azure SDKs to handle resource authorization.
// This package attempts to provide a single source for such a layer.
package azauth

import (
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"go.uber.org/zap"
)

const errorMsg = "no authorizer available"

// NoAuthorizerError indicates a failure to get an authorizer from any of (in order): File, CLI, and environment.
type NoAuthorizerError struct{}

// Error returns the static error message for total failure to authorize.
// More specific error messages will be logged, but not returned (as all but one will generally fail).
func (e NoAuthorizerError) Error() string {
	return errorMsg
}

// Config holds environment settings, cached authorizers, and global loggers.
// Notably, the environment settings contain the name of the Azure Cloud,
// required for parameterizing authentication for for each Cloud environment (e.g. Public, Fairfax, Mooncake).
type Config struct {
	userAgent string
	env       *azure.Environment
	Log       *zap.Logger
	Sugar     *zap.SugaredLogger
}

type Option func(*Config)

// New fetches and caches environment settings for resource authentication and initializes loggers.
func New(opts ...Option) (*Config, error) {
	var err error
	var settings auth.EnvironmentSettings
	var log *zap.Logger

	if log, err = zap.NewProduction(); err != nil {
		return nil, err
	}

	if settings, err = auth.GetSettingsFromEnvironment(); err != nil {
		return nil, err
	}

	log = log.Named("azauth")

	c := &Config{
		userAgent: "azauth",
		env:       &settings.Environment,
		Log:       log,
		Sugar:     log.Sugar(),
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

// GetArmAuthorizer returns a resource management authorizer for the current Azure Cloud environment.
// It will attempt to use a cached value from startup, or delegate to GetAuthorizerForResource.
func (c *Config) GetAuthorizer() (authorizer autorest.Authorizer, err error) {
	log := c.Sugar.With("method", "env")
	if authorizer, err = auth.NewAuthorizerFromEnvironment(); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)
	return nil, NoAuthorizerError{}
}

// GetAuthorizerForResource will return an authorizer to the resource or an error.
// It tries to use file, cli, and finally environment authentication, respectively.
func (c *Config) GetAuthorizerForResource(resource string) (authorizer autorest.Authorizer, err error) {
	log := c.Sugar.With("method", "env")
	if authorizer, err = auth.NewAuthorizerFromEnvironmentWithResource(resource); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)
	return nil, NoAuthorizerError{}
}

// GetArmAuthorizer returns a resource management authorizer for the current Azure Cloud environment.
// It will attempt to use a cached value from startup, or delegate to GetAuthorizerForResource.
func (c *Config) GetFileAuthorizer() (authorizer autorest.Authorizer, err error) {
	log := c.Sugar.With("method", "file")
	if authorizer, err = auth.NewAuthorizerFromFile(c.env.ResourceManagerEndpoint); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)
	return nil, NoAuthorizerError{}
}

// GetFileAuthorizerForResource will return a file-basedd authorizer to the resource or an error.
func (c *Config) GetFileAuthorizerForResource(resource string) (authorizer autorest.Authorizer, err error) {
	log := c.Sugar.With("method", "file")
	if authorizer, err = auth.NewAuthorizerFromFileWithResource(c.env.ResourceManagerEndpoint); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)
	return nil, NoAuthorizerError{}
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
