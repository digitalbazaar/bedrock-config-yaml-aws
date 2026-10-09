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
import {createCipheriv, createHash} from 'node:crypto';
import {DecryptCommand, KMSClient} from '@aws-sdk/client-kms';
import {getClient} from '@bedrock/aws-kms';
import {httpClient} from '@digitalbazaar/http-client';
import {readConfigFromAws} from '@bedrock/config-yaml-aws';
import {SecretsManagerClient} from '@aws-sdk/client-secrets-manager';
import sinon from 'sinon';

const {config, events} = bedrock;
config.ensureConfigOverride.enable = false;
config['aws-kms'].clients['config-yaml'] = {};
process.env.AWS_REGION = 'us-east-1';

sinon.stub(httpClient, 'put').resolves({text: async () => 'token'});
sinon.stub(httpClient, 'get').resolves({
  text: async () => process.env.FAKECLOUD_SECRET_ID ?? 'config-secret'
});

const plaintext = 'core:\n  sourceCore: true\napp:\n  sourceApp: true\n';
const key = Buffer.alloc(32, 1);
const iv = Buffer.alloc(12, 2);
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
let decryptedKey = key;
let send;
let decrypt;
let kms;
if(process.env.FAKECLOUD_SECRET_ID) {
  send = sinon.spy(SecretsManagerClient.prototype, 'send');
  kms = new KMSClient({
    region: 'us-east-1', endpoint: process.env.FAKECLOUD_ENDPOINT
  });
  // use FakeCloud for KMS and mock the native Nitro attestation call
  decrypt = sinon.stub(
    getClient({name: 'config-yaml'}), 'decryptWithAttestation').callsFake(
    async ({ciphertext, keyId}) => {
      const {Plaintext} = await kms.send(new DecryptCommand({
        CiphertextBlob: ciphertext, KeyId: keyId
      }));
      decryptedKey = Buffer.from(Plaintext);
      Plaintext.fill(0);
      return {plaintext: decryptedKey};
    });
} else {
  send = sinon.stub(SecretsManagerClient.prototype, 'send').resolves({
    SecretString: JSON.stringify({
      version: 1,
      format: 'yaml',
      kmsKeyId: 'test',
      encryptedDataKey: Buffer.from('ciphertext').toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      plaintextSha256: createHash('sha256').update(plaintext).digest('hex')
    })
  });
  decrypt = sinon.stub(
    getClient({name: 'config-yaml'}), 'decryptWithAttestation').resolves({
    plaintext: key
  });
}

let coreAtConfigure;
let appAtInit;
events.on('bedrock.configure', () => {
  coreAtConfigure = config.sourceCore;
  config.sourceApp = 'module-default';
});
events.on('bedrock.init', () => {
  appAtInit = config.sourceApp;
});
events.on('bedrock.started', async () => {
  console.log(JSON.stringify({
    coreAtConfigure,
    appAtInit,
    fetches: send.callCount,
    decrypts: decrypt.callCount,
    keyCleared: decryptedKey.equals(Buffer.alloc(32))
  }));
  kms?.destroy();
  await bedrock.shutdown();
});

// load YAML after the application has registered its configuration handlers
const {addConfigurationSource} = await import('@bedrock/config-yaml');
addConfigurationSource({name: 'aws', getConfig: readConfigFromAws});
await bedrock.start();
