# bedrock-config-yaml-aws ChangeLog

## Unreleased

### Added
- Add `readConfigFromAws()` for loading encrypted Bedrock YAML configuration
  from Secrets Manager using Nitro attestation.
- Read the configuration SecretId from the parent EC2 instance tag.
- Retry startup dependencies within the configured time limit.
