/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import * as bedrock from '@bedrock/core';
import {decryptEnvelope, parseEnvelope} from './envelope.js';
import {
  getClient, getDefaultRegion, getEc2InstanceTag
} from '@bedrock/aws-kms';
import {
  GetSecretValueCommand, SecretsManagerClient
} from '@aws-sdk/client-secrets-manager';
import {logger} from './logger.js';

import './config.js';

const {config, util: {BedrockError}} = bedrock;

const RETRYABLE_ERROR_NAMES = {
  kms_decrypt: new Set([
    'CredentialsProviderError', 'NetworkError', 'NotAllowedError',
    'TimeoutError'
  ]),
  region_discovery: new Set([
    'CredentialsProviderError', 'NetworkError', 'NotFoundError',
    'TimeoutError'
  ]),
  secret_fetch: new Set([
    'CredentialsProviderError', 'NetworkError', 'NotAllowedError',
    'NotFoundError', 'TimeoutError'
  ]),
  // instance tags may take time to appear in IMDS after boot
  secret_id_discovery: new Set([
    'NetworkError', 'NotFoundError', 'TimeoutError'
  ])
};

/**
 * Loads and decrypts the combined Bedrock YAML configuration from AWS.
 *
 * @returns {Promise<string|null>} - The YAML, or null when disabled.
 */
export async function readConfigFromAws() {
  const source = _getAwsSource();
  if(source === null) {
    return null;
  }
  config['aws-kms'].clients['config-yaml'] ??= {};
  const kmsClient = getClient({name: 'config-yaml'});
  const startedAt = Date.now();
  const deadline = startedAt + source.maxWaitMs;
  let delay = 5000;
  let attempt = 0;
  let stage = 'region_discovery';
  let lastError;
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(), source.maxWaitMs || 30000);
  let region;
  let secretsClient;
  let secretId;

  logger.info('AWS bedrock config load started', {
    secretIdTag: source.secretIdTag,
    maxWaitMs: source.maxWaitMs
  });

  try {
    while(attempt === 0 || !controller.signal.aborted) {
      attempt += 1;
      stage = 'region_discovery';
      try {
        region ??= await _beforeDeadline({
          promise: getDefaultRegion(), signal: controller.signal
        });
        secretsClient ??= new SecretsManagerClient({region});

        stage = 'secret_id_discovery';
        secretId ??= await _beforeDeadline({
          promise: _getSecretId({
            getEc2InstanceTag, secretIdTag: source.secretIdTag
          }),
          signal: controller.signal
        });

        stage = 'secret_fetch';
        const envelope = await _fetchEnvelope({
          client: secretsClient,
          command: new GetSecretValueCommand({SecretId: secretId}),
          secretId,
          region,
          signal: controller.signal
        });

        stage = 'kms_decrypt';
        const {plaintext: dataKey} = await _beforeDeadline({
          promise: kmsClient.decryptWithAttestation({
            ciphertext: envelope.encryptedDataKey,
            // require ciphertext encrypted with the key named in the envelope
            keyId: envelope.kmsKeyId
          }).then(result => {
            // a native decrypt may finish after startup has timed out
            if(controller.signal.aborted) {
              result.plaintext.fill(0);
            }
            return result;
          }),
          signal: controller.signal
        });

        stage = 'envelope_decrypt';
        let plaintext;
        try {
          plaintext = decryptEnvelope({envelope, key: dataKey});
        } finally {
          dataKey.fill(0);
        }

        logger.info('AWS bedrock config loaded', {
          attempt,
          region,
          secretId,
          envelopeVersion: envelope.version,
          kmsKeyId: envelope.kmsKeyId,
          plaintextSha256: envelope.plaintextSha256
        });
        const configText = new TextDecoder().decode(plaintext);
        // clearing the buffer does not clear the decoded string
        plaintext.fill(0);
        return configText;
      } catch(error) {
        lastError = error;
        const retryable = _isRetryable({stage, error});
        const remaining = deadline - Date.now();
        if(!retryable) {
          throw error;
        }
        if(remaining <= 0 || controller.signal.aborted) {
          throw new BedrockError(
            'Bedrock config did not become ready before the deadline.',
            'TimeoutError', {
              httpStatusCode: 504,
              public: false,
              dependencyStage: stage,
              errorName: error.name,
              attempt,
              maxWaitMs: source.maxWaitMs,
              cause: error
            });
        }
        const wait = Math.min(delay, remaining);
        logger.warning('AWS bedrock config dependency is not ready', {
          attempt,
          dependencyStage: stage,
          errorName: error.name,
          retryInMs: wait
        });
        await new Promise(resolve => setTimeout(resolve, wait));
        delay = Math.min(delay * 2, 60000);
      }
    }
    throw new BedrockError(
      'Bedrock config did not become ready before the deadline.',
      'TimeoutError', {
        httpStatusCode: 504,
        public: false,
        attempt,
        maxWaitMs: source.maxWaitMs,
        dependencyStage: stage,
        errorName: lastError?.name,
        cause: lastError
      });
  } finally {
    clearTimeout(timer);
    secretsClient?.destroy();
  }
}

async function _getSecretId({getEc2InstanceTag, secretIdTag}) {
  const secretId = await getEc2InstanceTag({name: secretIdTag});
  if(!secretId) {
    throw new BedrockError(
      'The EC2 instance SecretId tag is empty.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        secretIdTag
      });
  }
  return secretId;
}

async function _fetchEnvelope({client, command, secretId, region, signal}) {
  let response;
  try {
    response = await _beforeDeadline({
      promise: client.send(command, {abortSignal: signal}), signal
    });
  } catch(error) {
    const common = {
      secretId,
      region,
      awsErrorName: error.name,
      awsRequestId: error.$metadata?.requestId ?? null
    };
    if(error.name === 'ResourceNotFoundException') {
      throw new BedrockError(
        'The bedrock config secret was not found.',
        'NotFoundError', {
          ...common,
          httpStatusCode: 404,
          public: false,
          cause: error
        });
    }
    if(error.name === 'AccessDeniedException' ||
      error.name === 'AccessDenied') {
      throw new BedrockError(
        'Access to the bedrock config secret was denied.',
        'NotAllowedError', {
          ...common,
          httpStatusCode: 403,
          public: false,
          cause: error
        });
    }
    // the SDK retries service and transport failures before returning them
    throw error;
  }

  if(typeof response.SecretString !== 'string') {
    throw new BedrockError(
      'The bedrock config secret did not contain SecretString.',
      'DataError', {
        httpStatusCode: 500,
        public: false,
        secretId,
        region,
        secretVersionId: response.VersionId ?? null
      });
  }

  return parseEnvelope(response.SecretString);
}

function _isRetryable({stage, error}) {
  if(RETRYABLE_ERROR_NAMES[stage]?.has(error.name)) {
    return true;
  }
  // only retry AWS failures here. Malformed envelopes must fail immediately
  if(stage === 'secret_fetch' || stage === 'kms_decrypt') {
    const status = error.$metadata?.httpStatusCode;
    return error.$retryable !== undefined || status >= 500;
  }
  return false;
}

function _isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function _beforeDeadline({promise, signal}) {
  let abort;
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        abort = () => reject(new BedrockError(
          'AWS config startup deadline exceeded.', 'TimeoutError', {
            httpStatusCode: 504, public: false
          }));
        if(signal.aborted) {
          abort();
        } else {
          signal.addEventListener('abort', abort, {once: true});
        }
      })
    ]);
  } finally {
    signal.removeEventListener('abort', abort);
  }
}

function _getAwsSource() {
  const source = config['config-yaml-aws'];
  if(source === undefined) {
    return null;
  }
  if(!_isObject(source)) {
    throw new BedrockError(
      'The AWS bedrock config source is invalid.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false
      });
  }

  if(source.enabled !== true) {
    return null;
  }

  const {environment} = source;
  if(typeof source.secretIdTag !== 'string' ||
    source.secretIdTag.length === 0) {
    throw new BedrockError(
      'The AWS bedrock config SecretId tag is invalid.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false
      });
  }
  if(!Number.isSafeInteger(source.maxWaitMs) || source.maxWaitMs < 0 ||
    source.maxWaitMs > 2147483647) {
    throw new BedrockError(
      'The AWS bedrock config maxWaitMs is invalid.',
      'InvalidStateError', {
        httpStatusCode: 500,
        public: false,
        maxWaitMs: source.maxWaitMs
      });
  }
  if(environment !== 'nitro') {
    throw new BedrockError(
      'The configured AWS bedrock config environment is not implemented.',
      'NotSupportedError', {
        httpStatusCode: 501,
        public: false,
        environment: environment ?? null,
        supportedEnvironments: ['nitro']
      });
  }

  return source;
}
