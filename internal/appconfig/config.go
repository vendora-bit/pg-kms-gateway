package appconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string         `yaml:"listen"`
	Health         string         `yaml:"health"`
	Upstream       Upstream       `yaml:"upstream"`
	ClientTLS      ServerTLS      `yaml:"clientTLS"`
	Authentication Authentication `yaml:"authentication"`
	PolicyFile     string         `yaml:"policyFile"`
	BundleFile     string         `yaml:"bundleFile"`
	MetadataDSN    string         `yaml:"metadataDSNEnv"`
	KMS            KMS            `yaml:"kms"`
	Limits         Limits         `yaml:"limits"`
}

type Authentication struct {
	Mode                string `yaml:"mode"`
	ClientUsername      string `yaml:"clientUsername,omitempty"`
	ClientPasswordEnv   string `yaml:"clientPasswordEnv,omitempty"`
	UpstreamUsername    string `yaml:"upstreamUsername,omitempty"`
	UpstreamPasswordEnv string `yaml:"upstreamPasswordEnv,omitempty"`
	UpstreamDatabase    string `yaml:"upstreamDatabase,omitempty"`
}

type Upstream struct {
	Address    string `yaml:"address"`
	TLS        bool   `yaml:"tls"`
	ServerName string `yaml:"serverName"`
	CAFile     string `yaml:"caFile,omitempty"`
}

type ServerTLS struct {
	Required *bool  `yaml:"required,omitempty"`
	CertFile string `yaml:"certFile,omitempty"`
	KeyFile  string `yaml:"keyFile,omitempty"`
	CAFile   string `yaml:"clientCAFile,omitempty"`
}

func (s ServerTLS) IsRequired() bool {
	return s.Required == nil || *s.Required
}

type KMS struct {
	Provider string `yaml:"provider"`
	KeyRef   string `yaml:"keyRef"`
	Vault    Vault  `yaml:"vault,omitempty"`
	AWS      AWS    `yaml:"aws,omitempty"`
	Azure    Azure  `yaml:"azure,omitempty"`
}

type Vault struct {
	Address   string `yaml:"address"`
	Mount     string `yaml:"mount,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	TokenEnv  string `yaml:"tokenEnv"`
}

type AWS struct {
	Region string `yaml:"region"`
}

type Azure struct {
	VaultURL  string `yaml:"vaultURL"`
	Algorithm string `yaml:"algorithm,omitempty"`
}

type Limits struct {
	MessageBytes   int      `yaml:"messageBytes,omitempty"`
	MaxConnections int      `yaml:"maxConnections,omitempty"`
	DialTimeout    Duration `yaml:"dialTimeout,omitempty"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("config: duration must be a string such as 10s")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config: multiple YAML documents are not allowed")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":6432"
	}
	if c.Health == "" {
		c.Health = "127.0.0.1:8080"
	}
	if c.Upstream.Address == "" || c.PolicyFile == "" || c.BundleFile == "" || c.MetadataDSN == "" {
		return errors.New("config: upstream.address, policyFile, bundleFile and metadataDSNEnv are required")
	}
	if c.Authentication.Mode == "" {
		c.Authentication.Mode = "terminate-scram"
	}
	switch c.Authentication.Mode {
	case "relay":
	case "terminate-scram":
		if !c.ClientTLS.IsRequired() {
			return errors.New("config: terminate-scram authentication requires client TLS")
		}
		if c.Authentication.ClientUsername == "" || c.Authentication.ClientPasswordEnv == "" || c.Authentication.UpstreamUsername == "" || c.Authentication.UpstreamPasswordEnv == "" || c.Authentication.UpstreamDatabase == "" {
			return errors.New("config: terminate-scram requires clientUsername, clientPasswordEnv, upstreamUsername, upstreamPasswordEnv and upstreamDatabase")
		}
	default:
		return fmt.Errorf("config: unsupported authentication.mode %q", c.Authentication.Mode)
	}
	if c.KMS.KeyRef == "" {
		return errors.New("config: kms.keyRef is required")
	}
	switch c.KMS.Provider {
	case "vault-transit":
		if c.KMS.Vault.Address == "" || c.KMS.Vault.TokenEnv == "" {
			return errors.New("config: Vault provider requires kms.vault.address and tokenEnv")
		}
	case "aws-kms":
		if c.KMS.AWS.Region == "" {
			return errors.New("config: AWS KMS provider requires kms.aws.region")
		}
	case "gcp-kms":
	case "azure-key-vault":
		if c.KMS.Azure.VaultURL == "" {
			return errors.New("config: Azure provider requires kms.azure.vaultURL")
		}
	default:
		return fmt.Errorf("config: unsupported kms.provider %q", c.KMS.Provider)
	}
	if c.ClientTLS.IsRequired() && (c.ClientTLS.CertFile == "" || c.ClientTLS.KeyFile == "") {
		return errors.New("config: required client TLS needs certFile and keyFile")
	}
	if (c.ClientTLS.CertFile == "") != (c.ClientTLS.KeyFile == "") {
		return errors.New("config: client TLS certFile and keyFile must be set together")
	}
	if c.Upstream.TLS && strings.TrimSpace(c.Upstream.ServerName) == "" {
		return errors.New("config: upstream TLS requires serverName")
	}
	if c.Limits.MessageBytes == 0 {
		c.Limits.MessageBytes = 64 << 20
	}
	if c.Limits.MessageBytes < 1<<20 || c.Limits.MessageBytes > 1<<30 {
		return errors.New("config: limits.messageBytes must be between 1 MiB and 1 GiB")
	}
	if c.Limits.MaxConnections == 0 {
		c.Limits.MaxConnections = 1024
	}
	if c.Limits.MaxConnections < 1 || c.Limits.MaxConnections > 100_000 {
		return errors.New("config: limits.maxConnections must be between 1 and 100000")
	}
	if c.Limits.DialTimeout == 0 {
		c.Limits.DialTimeout = Duration(10 * time.Second)
	}
	if c.Limits.DialTimeout < Duration(time.Second) || c.Limits.DialTimeout > Duration(time.Minute) {
		return errors.New("config: limits.dialTimeout must be between 1s and 1m")
	}
	return nil
}

func (c Config) ClientTLSConfig() (*tls.Config, error) {
	if c.ClientTLS.CertFile == "" {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(c.ClientTLS.CertFile, c.ClientTLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: load client-facing TLS certificate: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if c.ClientTLS.CAFile != "" {
		pool, err := certificatePool(c.ClientTLS.CAFile)
		if err != nil {
			return nil, err
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func (c Config) UpstreamTLSConfig() (*tls.Config, error) {
	if !c.Upstream.TLS {
		return nil, nil
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.Upstream.ServerName}
	if c.Upstream.CAFile != "" {
		pool, err := certificatePool(c.Upstream.CAFile)
		if err != nil {
			return nil, err
		}
		config.RootCAs = pool
	}
	return config, nil
}

func certificatePool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read CA file %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("config: CA file %s contains no certificates", path)
	}
	return pool, nil
}
