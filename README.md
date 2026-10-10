# bedrock-config-yaml-aws

This package loads a Bedrock YAML config from AWS Secrets Manager inside a
Nitro Enclave. It uses `@bedrock/aws-kms` to decrypt the data key with Nitro
attestation. The application registers the loader with `@bedrock/config-yaml`.

## Usage

The package requires Node.js 24 or later and `@bedrock/core` and
`@bedrock/aws-kms` as peer dependencies. The application also installs
`@bedrock/config-yaml` to apply the returned YAML.

```js
import * as bedrock from '@bedrock/core';
import {readConfigFromAws} from '@bedrock/config-yaml-aws';

// import application modules here

// load YAML after the application's configuration handlers
import {addConfigurationSource} from '@bedrock/config-yaml';

addConfigurationSource({name: 'aws', getConfig: readConfigFromAws});
bedrock.start();
```

`readConfigFromAws()` returns the combined YAML as a string. It returns `null`
when the source is disabled. `@bedrock/config-yaml` fetches it once per process
and applies its `core` and `app` sections during the Bedrock configuration
events. Application initialization runs after the app config has been applied.

## Configuration

`BEDROCK_CONFIG_GZIP` or `BEDROCK_CONFIG` takes priority over registered
sources. In an enclave, these environment values are part of the measured
image. When neither is set, `@bedrock/config-yaml` calls the registered sources.

The image can enable the source before Bedrock starts:

```dockerfile
ENV BEDROCK_CONFIG_YAML_AWS_ENABLED=true
ENV BEDROCK_CONFIG_YAML_AWS_ENVIRONMENT=nitro
```

These variables set the defaults for `enabled` and `environment` in
`bedrock.config['config-yaml-aws']`. Only the string `true` enables the source. Applications can also set these config values
directly before the configuration events run.

The AWS source reads the EC2 instance tag named `BedrockConfigSecretId` by
default. This tag holds a secret name or ARN, not the secret itself. Its value
is passed to Secrets Manager as `SecretId`. The tag name may be
overridden with `secretIdTag`.

`maxWaitMs` sets the time limit for loading the config. The default
is `300000` milliseconds (five minutes). This limit covers instance metadata
lookups, AWS requests, and waits between retries. A value of `0` allows one
attempt with a 30-second limit and no retries.

Set `environment` to `'nitro'`, the supported AWS environment. Bedrock must
load and decrypt a valid config before startup can finish. If loading fails,
startup stops.

The loader retries errors that may clear as AWS services become ready. All
retries share the time limit set by `maxWaitMs`:

| Step | Errors that allow a retry |
| --- | --- |
| Region lookup | Network, not found, timeout, credentials not ready |
| Instance tag lookup | Network, not found, timeout |
| Secrets Manager | Network, not found, timeout, credentials not ready, access denied |
| KMS | Network, timeout, credentials not ready, access denied |

Secrets Manager and KMS also allow a retry when the SDK reports that its
retries are exhausted or AWS returns a 5xx response. Retrying access denied
allows time for new IAM policies to take effect. Invalid source settings,
invalid envelopes, failed ciphertext authentication, other decrypt errors,
and invalid YAML stop startup without a retry.

Retry logs show the step, error name, attempt number, and wait before the next
attempt. A timeout error includes the step and error name that caused it.

The source reads a version-1 encrypted envelope from Secrets Manager in the
application's default AWS region. It uses the `@bedrock/aws-kms` client named
`config-yaml` to decrypt the data key with Nitro attestation. The KMS `KeyId`
parameter is set to the envelope's `kmsKeyId`, so KMS checks that the key
matches. The loader then decrypts the YAML with AES-256-GCM and checks its
SHA-256 hash. It returns the YAML for `@bedrock/config-yaml` to parse and merge.

`@bedrock/aws-kms` reads the EC2 Instance Metadata Service (IMDS) using
`@digitalbazaar/http-client`.

## Development

Install the development dependencies and run lint from this directory:

```sh
npm install
npm run lint
```

Install the test dependencies and run the suite:

```sh
cd test
npm install
npm test
```
