package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	awssdkconfig "github.com/aws/aws-sdk-go-v2/config"
	awssvckms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/jackc/pgx/v5"

	"github.com/vendora-bit/pg-kms-gateway/internal/appconfig"
	"github.com/vendora-bit/pg-kms-gateway/internal/corpus"
	"github.com/vendora-bit/pg-kms-gateway/internal/gateway"
	"github.com/vendora-bit/pg-kms-gateway/internal/operator"
	"github.com/vendora-bit/pg-kms-gateway/internal/origin"
	"github.com/vendora-bit/pg-kms-gateway/internal/pgsession"
	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/telemetry"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/awskms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/azurekms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/gcpkms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/vaulttransit"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: pg-kms-gateway <serve|policy-check|corpus-verify|backfill|reencrypt|verify|keys-init|keys-rotate|keys-rewrap|keys-prune|version>")
	}
	switch arguments[0] {
	case "serve":
		return serve(arguments[1:])
	case "policy-check":
		return policyCheck(arguments[1:])
	case "corpus-verify":
		return corpusVerify(arguments[1:])
	case "keys-init", "keys-rotate", "keys-rewrap":
		return keys(arguments[0], arguments[1:])
	case "keys-prune":
		return pruneKeys(arguments[1:])
	case "backfill", "reencrypt", "verify":
		return operate(arguments[0], arguments[1:])
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func corpusVerify(arguments []string) error {
	set := flag.NewFlagSet("corpus-verify", flag.ContinueOnError)
	policyPath := set.String("policy", "", "path to policy YAML")
	corpusPath := set.String("corpus", "", "path to corpus JSON")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *policyPath == "" || *corpusPath == "" || set.NArg() != 0 {
		return errors.New("corpus-verify: exactly --policy and --corpus are required")
	}
	document, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	catalog, err := policy.Compile(document)
	if err != nil {
		return err
	}
	queries, err := corpus.Load(*corpusPath)
	if err != nil {
		return err
	}
	report, verifyErr := corpus.Verify(queries, catalog)
	fmt.Printf("profile=%s total=%d supported=%d rejected=%d failed=%d\n", queries.Profile, report.Total, report.Supported, report.Rejected, report.Failed)
	if verifyErr != nil {
		return fmt.Errorf("corpus-verify: %w", verifyErr)
	}
	return nil
}

func pruneKeys(arguments []string) error {
	config, err := configFlag("keys-prune", arguments)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	document, err := policy.Load(config.PolicyFile)
	if err != nil {
		return err
	}
	catalog, err := policy.Compile(document)
	if err != nil {
		return err
	}
	bundle, err := loadBundle(config.BundleFile)
	if err != nil {
		return err
	}
	providers, _, closeProvider, err := kmsProvider(ctx, config)
	if err != nil {
		return err
	}
	defer closeProvider()
	keyring, err := vaultkey.Open(ctx, bundle, providers)
	if err != nil {
		return err
	}
	dsn := os.Getenv(config.MetadataDSN)
	if dsn == "" {
		return fmt.Errorf("keys-prune: database DSN environment variable %s is unset", config.MetadataDSN)
	}
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("keys-prune: connect to PostgreSQL: %w", err)
	}
	defer connection.Close(context.Background())
	if _, err := origin.Discover(ctx, connection, catalog); err != nil {
		return err
	}
	engine := operator.Engine{Connection: connection, Processor: operator.Processor{Keyring: keyring, Domain: catalog.KeyDomain()}, BatchSize: 500}
	for _, field := range catalog.Fields() {
		verification, err := engine.VerifyField(ctx, field)
		if err != nil {
			return err
		}
		if !verification.Clean() {
			return fmt.Errorf("keys-prune: verification is not clean for %s.%s.%s", field.Schema, field.Table, field.Column)
		}
	}
	pruned, removed, err := vaultkey.PruneDecryptOnly(bundle)
	if err != nil {
		return err
	}
	if err := vaultkey.SaveAtomic(config.BundleFile, pruned); err != nil {
		return err
	}
	fmt.Printf("pruned %d decrypt-only key versions\n", removed)
	return nil
}

func operate(command string, arguments []string) error {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	path := set.String("config", "", "path to the YAML configuration")
	batch := set.Int("batch", 250, "rows per transaction (1..10000)")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 || *batch < 1 || *batch > 10_000 {
		return fmt.Errorf("%s: --config and a valid --batch are required", command)
	}
	config, err := appconfig.Load(*path)
	if err != nil {
		return err
	}
	document, err := policy.Load(config.PolicyFile)
	if err != nil {
		return err
	}
	catalog, err := policy.Compile(document)
	if err != nil {
		return err
	}
	bundle, err := loadBundle(config.BundleFile)
	if err != nil {
		return err
	}
	if bundle.Domain != catalog.KeyDomain() {
		return errors.New("operator: policy and bundle key domains differ")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	providers, _, closeProvider, err := kmsProvider(ctx, config)
	if err != nil {
		return err
	}
	defer closeProvider()
	keyring, err := vaultkey.Open(ctx, bundle, providers)
	if err != nil {
		return err
	}
	dsn, exists := os.LookupEnv(config.MetadataDSN)
	if !exists || dsn == "" {
		return fmt.Errorf("operator: database DSN environment variable %s is unset", config.MetadataDSN)
	}
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("operator: connect to PostgreSQL: %w", err)
	}
	defer connection.Close(context.Background())
	if _, err := origin.Discover(ctx, connection, catalog); err != nil {
		return err
	}
	mode := operator.Backfill
	if command == "reencrypt" {
		mode = operator.Reencrypt
	}
	engine := operator.Engine{Connection: connection, Processor: operator.Processor{Keyring: keyring, Domain: catalog.KeyDomain()}, BatchSize: *batch}
	if command == "verify" {
		clean := true
		for _, field := range catalog.Fields() {
			verification, err := engine.VerifyField(ctx, field)
			if err != nil {
				return err
			}
			fmt.Printf("%s.%s.%s: scanned=%d plaintext=%d old_key=%d invalid=%d blind_mismatch=%d\n", field.Schema, field.Table, field.Column, verification.Scanned, verification.PlaintextRows, verification.OldKeyRows, verification.InvalidRows, verification.BlindMismatch)
			clean = clean && verification.Clean()
		}
		if !clean {
			return errors.New("verify: protected data verification failed")
		}
		fmt.Println("verification passed")
		return nil
	}
	var total operator.Stats
	for _, field := range catalog.Fields() {
		stats, verification, err := engine.RunAndVerifyField(ctx, field, mode)
		if err != nil {
			return err
		}
		total.Scanned += stats.Scanned
		total.Updated += stats.Updated
		total.Unchanged += stats.Unchanged
		total.Conflicted += stats.Conflicted
		fmt.Printf("%s.%s.%s: scanned=%d updated=%d unchanged=%d conflicted=%d verified=%d\n", field.Schema, field.Table, field.Column, stats.Scanned, stats.Updated, stats.Unchanged, stats.Conflicted, verification.Scanned)
	}
	fmt.Printf("total: scanned=%d updated=%d unchanged=%d conflicted=%d\n", total.Scanned, total.Updated, total.Unchanged, total.Conflicted)
	return nil
}

func configFlag(name string, arguments []string) (appconfig.Config, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	path := set.String("config", "", "path to the YAML configuration")
	if err := set.Parse(arguments); err != nil {
		return appconfig.Config{}, err
	}
	if *path == "" || set.NArg() != 0 {
		return appconfig.Config{}, fmt.Errorf("%s: exactly --config is required", name)
	}
	return appconfig.Load(*path)
}

func policyCheck(arguments []string) error {
	set := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	path := set.String("policy", "", "path to policy YAML")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || set.NArg() != 0 {
		return errors.New("policy-check: exactly --policy is required")
	}
	document, err := policy.Load(*path)
	if err != nil {
		return err
	}
	catalog, err := policy.Compile(document)
	if err != nil {
		return err
	}
	fmt.Printf("valid policy %q: %d protected columns, key domain %q\n", catalog.Name(), len(catalog.Fields()), catalog.KeyDomain())
	return nil
}

func keys(command string, arguments []string) error {
	config, err := configFlag(command, arguments)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	providers, target, closeProvider, err := kmsProvider(ctx, config)
	if err != nil {
		return err
	}
	defer closeProvider()
	now := time.Now().UTC()
	switch command {
	case "keys-init":
		if _, err := os.Stat(config.BundleFile); err == nil {
			return errors.New("keys-init: bundle already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keys-init: inspect bundle: %w", err)
		}
		document, err := policy.Load(config.PolicyFile)
		if err != nil {
			return err
		}
		bundle, _, err := vaultkey.New(ctx, document.Spec.KeyDomain, target, providers, now)
		if err != nil {
			return err
		}
		if err := vaultkey.SaveAtomic(config.BundleFile, bundle); err != nil {
			return err
		}
		fmt.Printf("created bundle with active key %s\n", bundle.Active)
	case "keys-rotate", "keys-rewrap":
		bundle, err := loadBundle(config.BundleFile)
		if err != nil {
			return err
		}
		if command == "keys-rotate" {
			next, _, err := vaultkey.Rotate(ctx, bundle, target, providers, now)
			if err != nil {
				return err
			}
			if err := vaultkey.SaveAtomic(config.BundleFile, next); err != nil {
				return err
			}
			fmt.Printf("rotated active data key to %s\n", next.Active)
		} else {
			next, err := vaultkey.Rewrap(ctx, bundle, target, providers)
			if err != nil {
				return err
			}
			if err := vaultkey.SaveAtomic(config.BundleFile, next); err != nil {
				return err
			}
			fmt.Printf("rewrapped %d data keys\n", len(next.Keys))
		}
	}
	return nil
}

func serve(arguments []string) error {
	config, err := configFlag("serve", arguments)
	if err != nil {
		return err
	}
	document, err := policy.Load(config.PolicyFile)
	if err != nil {
		return err
	}
	catalog, err := policy.Compile(document)
	if err != nil {
		return err
	}
	bundle, err := loadBundle(config.BundleFile)
	if err != nil {
		return err
	}
	if bundle.Domain != catalog.KeyDomain() {
		return errors.New("serve: policy key domain and key bundle domain differ")
	}
	startupContext, startupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startupCancel()
	providers, _, closeProvider, err := kmsProvider(startupContext, config)
	if err != nil {
		return err
	}
	defer closeProvider()
	keyring, err := vaultkey.Open(startupContext, bundle, providers)
	if err != nil {
		return err
	}
	dsn, exists := os.LookupEnv(config.MetadataDSN)
	if !exists || dsn == "" {
		return fmt.Errorf("serve: metadata DSN environment variable %s is unset", config.MetadataDSN)
	}
	metadataConnection, err := pgx.Connect(startupContext, dsn)
	if err != nil {
		return fmt.Errorf("serve: connect for schema discovery: %w", err)
	}
	resolver, discoverErr := origin.Discover(startupContext, metadataConnection, catalog)
	closeErr := metadataConnection.Close(startupContext)
	if discoverErr != nil {
		return discoverErr
	}
	if closeErr != nil {
		return fmt.Errorf("serve: close schema discovery connection: %w", closeErr)
	}
	clientTLS, err := config.ClientTLSConfig()
	if err != nil {
		return err
	}
	upstreamTLS, err := config.UpstreamTLSConfig()
	if err != nil {
		return err
	}
	metrics := &telemetry.Metrics{}
	var terminateAuth *gateway.TerminationAuth
	if config.Authentication.Mode == "terminate-scram" {
		clientPassword := os.Getenv(config.Authentication.ClientPasswordEnv)
		upstreamPassword := os.Getenv(config.Authentication.UpstreamPasswordEnv)
		if clientPassword == "" || upstreamPassword == "" {
			return errors.New("serve: authentication password environment variables must be set")
		}
		terminateAuth = &gateway.TerminationAuth{
			ClientUsername: config.Authentication.ClientUsername, ClientPassword: clientPassword,
			UpstreamUsername: config.Authentication.UpstreamUsername, UpstreamPassword: upstreamPassword,
			UpstreamDatabase: config.Authentication.UpstreamDatabase,
		}
	}
	server, err := gateway.New(gateway.Config{
		UpstreamAddress: config.Upstream.Address, ClientTLS: clientTLS, RequireClientTLS: config.ClientTLS.IsRequired(),
		UpstreamTLS: upstreamTLS, RequireUpstreamTLS: config.Upstream.TLS, DialTimeout: time.Duration(config.Limits.DialTimeout),
		MaxMessageBytes: config.Limits.MessageBytes,
		MaxConnections:  config.Limits.MaxConnections,
		NewMachine:      func() (*pgsession.Machine, error) { return pgsession.New(catalog, keyring, resolver, metrics) },
		Metrics:         metrics,
		TerminateAuth:   terminateAuth,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return fmt.Errorf("serve: listen: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	health := &http.Server{Addr: config.Health, Handler: healthHandler(metrics), ReadHeaderTimeout: 5 * time.Second}
	healthErrors := make(chan error, 1)
	go func() {
		if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			healthErrors <- err
		}
	}()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(ctx, listener) }()
	slog.Info("gateway ready", "listen", config.Listen, "health", config.Health, "policy", catalog.Name(), "active_key", keyring.ActiveKeyID())
	select {
	case err := <-serveErrors:
		stop()
		return err
	case err := <-healthErrors:
		stop()
		return fmt.Errorf("serve: health server: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return health.Shutdown(shutdownContext)
	}
}

func kmsProvider(ctx context.Context, config appconfig.Config) (map[string]vaultkey.Provider, vaultkey.Target, func(), error) {
	var provider vaultkey.Provider
	closeProvider := func() {}
	switch config.KMS.Provider {
	case "vault-transit":
		value, err := vaulttransit.New(vaulttransit.Config{
			Address: config.KMS.Vault.Address, Mount: config.KMS.Vault.Mount, Namespace: config.KMS.Vault.Namespace,
			Token: vaulttransit.EnvToken{Name: config.KMS.Vault.TokenEnv},
		})
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, err
		}
		provider = value
	case "aws-kms":
		awsConfig, err := awssdkconfig.LoadDefaultConfig(ctx, awssdkconfig.WithRegion(config.KMS.AWS.Region))
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, fmt.Errorf("initialize AWS credential chain: %w", err)
		}
		value, err := awskms.New(awssvckms.NewFromConfig(awsConfig))
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, err
		}
		provider = value
	case "gcp-kms":
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, fmt.Errorf("initialize GCP credential chain: %w", err)
		}
		closeProvider = func() { _ = client.Close() }
		value, err := gcpkms.New(client)
		if err != nil {
			closeProvider()
			return nil, vaultkey.Target{}, func() {}, err
		}
		provider = value
	case "azure-key-vault":
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, fmt.Errorf("initialize Azure credential chain: %w", err)
		}
		client, err := azkeys.NewClient(config.KMS.Azure.VaultURL, credential, nil)
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, fmt.Errorf("initialize Azure Key Vault client: %w", err)
		}
		value, err := azurekms.New(client, azkeys.EncryptionAlgorithm(config.KMS.Azure.Algorithm))
		if err != nil {
			return nil, vaultkey.Target{}, closeProvider, err
		}
		provider = value
	default:
		return nil, vaultkey.Target{}, closeProvider, fmt.Errorf("unsupported KMS provider %q", config.KMS.Provider)
	}
	providers := map[string]vaultkey.Provider{provider.Name(): provider}
	return providers, vaultkey.Target{Provider: provider.Name(), KeyRef: config.KMS.KeyRef}, closeProvider, nil
}

func loadBundle(path string) (vaultkey.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return vaultkey.Bundle{}, fmt.Errorf("read key bundle: %w", err)
	}
	return vaultkey.Parse(data)
}

func healthHandler(metrics *telemetry.Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.Handle("/metrics", metrics.Handler())
	return mux
}
