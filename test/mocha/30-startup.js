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

import {createCipheriv, createHash, randomBytes} from 'node:crypto';
import {
  CreateKeyCommand, EncryptCommand, KMSClient, ScheduleKeyDeletionCommand
} from '@aws-sdk/client-kms';
import {
  CreateSecretCommand, DeleteSecretCommand, SecretsManagerClient
} from '@aws-sdk/client-secrets-manager';
import {execFile} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const execFileAsync = promisify(execFile);

describe('AWS configuration at Bedrock startup', () => {
  it('applies core and app config before module initialization', async () => {
    const fixture = fileURLToPath(new URL('../fixtures/startup.js',
      import.meta.url));
    const {stdout} = await execFileAsync(process.execPath, [
      ...process.execArgv, fixture, '--silent'
    ], {
      timeout: 10000,
      env: {
        ...process.env, BEDROCK_CONFIG: '', BEDROCK_CONFIG_GZIP: '',
        BEDROCK_CONFIG_YAML_AWS_ENABLED: 'true',
        BEDROCK_CONFIG_YAML_AWS_ENVIRONMENT: 'nitro'
      }
    });
    JSON.parse(stdout).should.deep.equal({
      coreAtConfigure: true,
      appAtInit: true,
      fetches: 1,
      decrypts: 1,
      keyCleared: true
    });
  });
});

const describeFakeCloud = process.env.FAKECLOUD_ENDPOINT ?
  describe : describe.skip;

describeFakeCloud('AWS configuration with FakeCloud', () => {
  it('loads encrypted config before app initialization', async () => {
    const endpoint = process.env.FAKECLOUD_ENDPOINT;
    const options = {
      endpoint, region: 'us-east-1',
      credentials: {accessKeyId: 'test', secretAccessKey: 'test'}
    };
    const kms = new KMSClient(options);
    const secrets = new SecretsManagerClient(options);
    let keyId;
    let secretId;
    const key = randomBytes(32);
    try {
      const {KeyMetadata} = await kms.send(new CreateKeyCommand({}));
      keyId = KeyMetadata.Arn;
      const {CiphertextBlob} = await kms.send(new EncryptCommand({
        KeyId: keyId, Plaintext: key
      }));
      const plaintext = 'core:\n  sourceCore: true\napp:\n  sourceApp: true\n';
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([
        cipher.update(plaintext), cipher.final()
      ]);
      const {ARN} = await secrets.send(new CreateSecretCommand({
        Name: `config-yaml-test-${randomBytes(8).toString('hex')}`,
        SecretString: JSON.stringify({
          version: 1, format: 'yaml', kmsKeyId: keyId,
          encryptedDataKey: Buffer.from(CiphertextBlob).toString('base64'),
          iv: iv.toString('base64'),
          authTag: cipher.getAuthTag().toString('base64'),
          ciphertext: ciphertext.toString('base64'),
          plaintextSha256: createHash('sha256').update(plaintext).digest('hex')
        })
      }));
      secretId = ARN;
      const fixture = fileURLToPath(new URL('../fixtures/startup.js',
        import.meta.url));
      const {stdout} = await execFileAsync(process.execPath, [
        ...process.execArgv, fixture, '--silent'
      ], {
        timeout: 20000,
        env: {
          ...process.env, BEDROCK_CONFIG: '', BEDROCK_CONFIG_GZIP: '',
          BEDROCK_CONFIG_YAML_AWS_ENABLED: 'true',
          BEDROCK_CONFIG_YAML_AWS_ENVIRONMENT: 'nitro',
          FAKECLOUD_SECRET_ID: secretId,
          AWS_ENDPOINT_URL_SECRETS_MANAGER: endpoint,
          AWS_ACCESS_KEY_ID: 'test', AWS_SECRET_ACCESS_KEY: 'test',
          AWS_SESSION_TOKEN: ''
        }
      });
      JSON.parse(stdout).should.deep.equal({
        coreAtConfigure: true, appAtInit: true, fetches: 1,
        decrypts: 1, keyCleared: true
      });
    } finally {
      key.fill(0);
      try {
        if(secretId) {
          await secrets.send(new DeleteSecretCommand({
            SecretId: secretId, ForceDeleteWithoutRecovery: true
          }));
        }
        if(keyId) {
          await kms.send(new ScheduleKeyDeletionCommand({
            KeyId: keyId, PendingWindowInDays: 7
          }));
        }
      } finally {
        kms.destroy();
        secrets.destroy();
      }
    }
  });
});
