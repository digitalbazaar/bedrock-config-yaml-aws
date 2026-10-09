/*!
 * Copyright 2026 Digital Bazaar, Inc.
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
import {createCipheriv, createHash} from 'node:crypto';
import {config} from '@bedrock/core';
import {getClient} from '@bedrock/aws-kms';
import {httpClient} from '@digitalbazaar/http-client';
import {readConfigFromAws} from '@bedrock/config-yaml-aws';
import {SecretsManagerClient} from '@aws-sdk/client-secrets-manager';
import sinon from 'sinon';

describe('AWS config source', () => {
  const source = config['config-yaml-aws'];
  const environmentVariable = 'AWS_REGION';
  let original;
  let originalEnvironment;

  beforeEach(() => {
    original = {...source};
    originalEnvironment = process.env[environmentVariable];
    process.env[environmentVariable] = 'us-east-1';
  });

  afterEach(() => {
    sinon.restore();
    Object.assign(source, original);
    if(originalEnvironment === undefined) {
      delete process.env[environmentVariable];
    } else {
      process.env[environmentVariable] = originalEnvironment;
    }
  });

  it('is disabled by default', async () => {
    should.equal(await readConfigFromAws(), null);
  });

  it('rejects an invalid maxWaitMs before discovery', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    source.maxWaitMs = -1;

    await readConfigFromAws().should.be.rejectedWith(
      'The AWS bedrock config maxWaitMs is invalid.');
  });

  it('rejects an unsupported environment before discovery', async () => {
    source.enabled = true;
    source.environment = 'standard';

    await readConfigFromAws().should.be.rejectedWith(
      'The configured AWS bedrock config environment is not implemented.');
  });

  it('rejects non-finite startup budgets before discovery', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    for(const value of [NaN, Infinity, -Infinity]) {
      source.maxWaitMs = value;
      await readConfigFromAws().should.be.rejectedWith(
        'The AWS bedrock config maxWaitMs is invalid.');
    }
  });

  it('times out an AWS request that never settles', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    source.maxWaitMs = 20;
    sinon.stub(httpClient, 'put').resolves({text: async () => 'token'});
    sinon.stub(httpClient, 'get').resolves({text: async () => 'secret'});
    sinon.stub(SecretsManagerClient.prototype, 'send').returns(
      new Promise(() => {}));

    await readConfigFromAws().should.be.rejectedWith(
      'Bedrock config did not become ready before the deadline.');
  });

  it('ends retries when the startup budget expires', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    source.maxWaitMs = 10000;
    const clock = sinon.useFakeTimers();
    sinon.stub(httpClient, 'put').resolves({text: async () => 'token'});
    sinon.stub(httpClient, 'get').resolves({text: async () => 'secret'});
    const send = sinon.stub(SecretsManagerClient.prototype, 'send').rejects(
      Object.assign(new Error('not ready'), {
        name: 'ResourceNotFoundException'
      }));
    const load = readConfigFromAws().catch(error => error);

    await clock.tickAsync(10001);
    const error = await load;
    error.name.should.equal('TimeoutError');
    error.details.maxWaitMs.should.equal(10000);
    error.details.dependencyStage.should.equal('secret_fetch');
    sinon.assert.calledTwice(send);
  });

  it('does not retry when maxWaitMs is zero', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    source.maxWaitMs = 0;
    sinon.stub(httpClient, 'put').resolves({text: async () => 'token'});
    sinon.stub(httpClient, 'get').resolves({text: async () => 'secret'});
    const send = sinon.stub(SecretsManagerClient.prototype, 'send').rejects(
      Object.assign(new Error('not ready'), {
        name: 'ResourceNotFoundException'
      }));

    await readConfigFromAws().should.be.rejectedWith(
      'Bedrock config did not become ready before the deadline.');
    sinon.assert.calledOnce(send);
  });

  it('decrypts with attestation and clears the data key', async () => {
    source.enabled = true;
    source.environment = 'nitro';
    sinon.stub(httpClient, 'put').resolves({text: async () => 'token'});
    sinon.stub(httpClient, 'get').resolves({text: async () => 'secret'});
    const key = Buffer.alloc(32, 1);
    const iv = Buffer.alloc(12, 2);
    const plaintext = 'core:\n  aws-core-test: true\n' +
      'app:\n  aws-app-test: true\n';
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext), cipher.final()
    ]);
    const send = sinon.stub(SecretsManagerClient.prototype, 'send').resolves({
      SecretString: JSON.stringify({
        version: 1, format: 'yaml', kmsKeyId: 'test',
        encryptedDataKey: Buffer.from('ciphertext').toString('base64'),
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        plaintextSha256: createHash('sha256').update(plaintext).digest('hex')
      })
    });
    config['aws-kms'].clients['config-yaml'] ??= {};
    const decrypt = sinon.stub(
      getClient({name: 'config-yaml'}), 'decryptWithAttestation').resolves({
      plaintext: key
    });

    const content = await readConfigFromAws();
    content.should.equal(plaintext);
    key.equals(Buffer.alloc(32)).should.equal(true);
    sinon.assert.calledOnce(send);
    sinon.assert.calledOnce(decrypt);
  });
});
