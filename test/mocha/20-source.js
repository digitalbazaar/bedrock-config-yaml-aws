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
import {config} from '@bedrock/core';
import {readConfigFromAws} from '@bedrock/config-yaml-aws';

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

});
