// This package provides some utility tooling for authorization to Azure resources.
// Many projects build a layer like this on top of the Azure SDKs to handle resource authorization.
// This package attempts to provide a single source for such a layer.
package azauth

import (
	"github.com/Azure/go-autorest/autorest"
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
	userAgent     string
	Log           *zap.Logger
	Sugar         *zap.SugaredLogger
	settings      *auth.EnvironmentSettings
	armAuthorizer *autorest.Authorizer
}

type Option func(*Config) *Config

// New fetches and caches environment settings for resource authentication and initializes loggers.
func New(opts ...Option) (*Config, error) {
	var err error
	var settings auth.EnvironmentSettings
	var log *zap.Logger

	if settings, err = auth.GetSettingsFromEnvironment(); err != nil {
		return nil, err
	}

	if log, err = zap.NewProduction(); err != nil {
		return nil, err
	}

	log = log.Named("azauth")

	c := &Config{
		userAgent: "azauth",
		settings:  &settings,
		Log:       log,
		Sugar:     log.Sugar(),
	}

	for _, opt := range opts {
		c = opt(c)
	}

	return c, nil
}

// UserAgent provides a method of setting the user agent on the client.
func UserAgent(userAgent string) Option {
	return func(c *Config) *Config {
		c.userAgent = userAgent
		return c
	}
}

// SetAuthorizers initializes and caches all commonly used authorizers.
func (c *Config) SetAuthorizers() error {
	if err := c.setArmAuthorizer(); err != nil {
		return err
	}
	return nil
}

func (c *Config) setArmAuthorizer() error {
	armAuthorizer, err := c.GetArmAuthorizer()
	if err != nil {
		return err
	}
	c.armAuthorizer = &armAuthorizer
	return nil
}

// GetArmAuthorizer returns a resource management authorizer for the current Azure Cloud environment.
// It will attempt to use a cached value from startup, or delegate to GetAuthorizerForResource.
func (c *Config) GetArmAuthorizer() (autorest.Authorizer, error) {
	// should just return immediately? or set lazily?
	if c.armAuthorizer != nil {
		c.Sugar.Info("using cached arm authorizer")
		return *c.armAuthorizer, nil
	}
	return c.GetAuthorizerForResource(c.settings.Environment.ResourceManagerEndpoint)
}

// GetAuthorizerForResource will return an authorizer to the resource or an error.
// It tries to use file, cli, and finally environment authentication, respectively.
func (c *Config) GetAuthorizerForResource(resource string) (authorizer autorest.Authorizer, err error) {
	log := c.Sugar.With("method", "file")
	if authorizer, err = auth.NewAuthorizerFromFileWithResource(resource); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)

	log = c.Sugar.With("method", "cli")
	if authorizer, err = auth.NewAuthorizerFromCLIWithResource(resource); err == nil {
		log.Info("ok")
		return
	}
	log.Error(err)

	log = c.Sugar.With("method", "env")
	if authorizer, err = auth.NewAuthorizerFromEnvironmentWithResource(resource); err == nil {
		log.Info("ok")
		return
	}

	log.Error(err)
	return nil, NoAuthorizerError{}
}

// AuthorizeClientForResource tries to fetch an authorizer using GetAuthorizerForResource and inject it into a client.
func (c *Config) AuthorizeClientForResource(resource string, client *autorest.Client, userAgent string) (err error) {
	if authorizer, err := c.GetAuthorizerForResource(resource); err == nil {
		client.Authorizer = authorizer
		return client.AddToUserAgent(userAgent)
	}
	return
}
