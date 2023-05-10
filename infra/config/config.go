package config

import (
	"github.com/spf13/viper"
)

// Config stores all configuration of the application.
// The values are read by viper from a config file or environment variable.
type Config struct {
	ServiceName                  string `mapstructure:"SERVICE_NAME"`
	ServiceVersion               string `mapstructure:"SERVICE_VERSION"`
	Environment                  string `mapstructure:"ENVIRONMENT"`
	DBDriver                     string `mapstructure:"DB_DRIVER"`
	DBDsn                        string `mapstructure:"DB_DSN"`
	HTTPServerPort               int    `mapstructure:"HTTP_SERVER_PORT"`
	GRPCServerAddress            string `mapstructure:"GRPC_SERVER_ADDRESS"`
	GRPCServerUserServiceAddress string `mapstructure:"GRPC_SERVER_USER_SERVICE_ADDRESS"`
	JwtID                        string `mapstructure:"JWT_ID"`
}

// ProvideConfig reads configuration from file or environment variables.
func ProvideConfig() (config Config, err error) {
	// TODO: move to lib
	viper.AddConfigPath("./config")
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
