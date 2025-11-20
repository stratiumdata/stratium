package key_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var _ secretFetcher = (*AWSSecretsManagerFetcher)(nil)

// AWSSecretsManagerFetcher retrieves secret payloads and caches clients per region/endpoint
type AWSSecretsManagerFetcher struct {
	mu      sync.Mutex
	clients map[string]*secretsmanager.Client
}

func NewAWSSecretsManagerFetcher() *AWSSecretsManagerFetcher {
	return &AWSSecretsManagerFetcher{
		clients: make(map[string]*secretsmanager.Client),
	}
}

func (f *AWSSecretsManagerFetcher) FetchSecret(ctx context.Context, region, endpoint, secretID, versionID, versionStage string) (string, error) {
	if secretID == "" {
		return "", fmt.Errorf("secret id is required")
	}
	if region == "" {
		return "", fmt.Errorf("region is required to read secret %s", secretID)
	}

	client, err := f.getClient(ctx, region, endpoint)
	if err != nil {
		return "", err
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	}
	if versionID != "" {
		input.VersionId = &versionID
	}
	if versionStage != "" {
		input.VersionStage = &versionStage
	}

	output, err := client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to fetch secret %s: %w", secretID, err)
	}

	if output.SecretString != nil {
		return *output.SecretString, nil
	}

	if len(output.SecretBinary) > 0 {
		return string(output.SecretBinary), nil
	}

	return "", fmt.Errorf("secret %s did not return string or binary payload", secretID)
}

func (f *AWSSecretsManagerFetcher) getClient(ctx context.Context, region, endpoint string) (*secretsmanager.Client, error) {
	key := region + "|" + endpoint

	f.mu.Lock()
	defer f.mu.Unlock()

	if client, ok := f.clients[key]; ok {
		return client, nil
	}

	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration for region %s: %w", region, err)
	}

	opts := []func(*secretsmanager.Options){}
	if endpoint != "" {
		resolver := secretsmanager.EndpointResolverFunc(func(region string, options secretsmanager.EndpointResolverOptions) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:           endpoint,
				SigningRegion: region,
			}, nil
		})
		opts = append(opts, func(o *secretsmanager.Options) {
			o.EndpointResolver = resolver
		})
	}

	client := secretsmanager.NewFromConfig(cfg, opts...)
	f.clients[key] = client
	return client, nil
}

func extractFieldFromJSON(payload, field string) (string, error) {
	if field == "" {
		return payload, nil
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return "", fmt.Errorf("failed to parse secret JSON: %w", err)
	}

	value, ok := parsed[field]
	if !ok {
		return "", fmt.Errorf("secret JSON does not contain field %q", field)
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret field %q is not a string value", field)
	}

	return strValue, nil
}
