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
import {createDecipheriv, createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';

const {util: {BedrockError}} = bedrock;

/**
 * Parses and validates a version-1 encrypted config envelope.
 *
 * @param {string} content - The JSON-encoded envelope.
 *
 * @returns {object} The envelope with its binary fields decoded.
 */
export function parseEnvelope(content) {
  let envelope;
  try {
    envelope = JSON.parse(content);
  } catch(cause) {
    throw new BedrockError(
      'The bedrock config SecretString is not valid JSON.',
      'SyntaxError', {
        httpStatusCode: 500,
        public: false,
        cause
      });
  }

  if(!_isObject(envelope) || envelope.version !== 1 ||
    envelope.format !== 'yaml') {
    throw new BedrockError(
      'The bedrock config envelope format is not supported.',
      'NotSupportedError', {
        httpStatusCode: 500,
        public: false,
        expectedVersion: 1,
        actualVersion: envelope?.version ?? null,
        expectedFormat: 'yaml',
        actualFormat: envelope?.format ?? null
      });
  }

  for(const name of [
    'kmsKeyId', 'encryptedDataKey', 'iv', 'authTag', 'ciphertext',
    'plaintextSha256'
  ]) {
    if(typeof envelope[name] !== 'string' || envelope[name].length === 0) {
      throw new BedrockError(
        'The bedrock config envelope is incomplete.',
        'DataError', {
          httpStatusCode: 500,
          public: false,
          field: name
        });
    }
  }

  for(const [name, expectedBytes] of [
    ['encryptedDataKey', null],
    ['iv', 12],
    ['authTag', 16],
    ['ciphertext', null]
  ]) {
    const value = _decodeBase64(envelope[name]);
    if(!value || (expectedBytes !== null && value.length !== expectedBytes)) {
      throw new BedrockError(
        'A bedrock config envelope field is invalid.',
        'DataError', {
          httpStatusCode: 500,
          public: false,
          field: name,
          expectedBytes,
          actualBytes: value?.length ?? null
        });
    }
    envelope[name] = value;
  }

  const hash = Buffer.from(envelope.plaintextSha256, 'hex');
  if(hash.length !== 32 ||
    hash.toString('hex') !== envelope.plaintextSha256) {
    throw new BedrockError(
      'The bedrock config plaintext hash is invalid.',
      'DataError', {
        httpStatusCode: 500,
        public: false,
        hashLength: envelope.plaintextSha256.length
      });
  }

  return envelope;
}

/**
 * Authenticates and decrypts a parsed config envelope.
 *
 * @param {object} options - The options to use.
 * @param {object} options.envelope - The parsed envelope.
 * @param {Uint8Array} options.key - The 32-byte AES data key.
 *
 * @returns {Uint8Array} The decrypted config bytes.
 */
export function decryptEnvelope({envelope, key}) {
  if(!(key instanceof Uint8Array) || key.length !== 32) {
    throw new BedrockError(
      'The decrypted bedrock config data key is invalid.',
      'DataError', {
        httpStatusCode: 500,
        public: false,
        expectedBytes: 32,
        actualBytes: key instanceof Uint8Array ? key.length : null
      });
  }

  let plaintext;
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm', key, envelope.iv, {authTagLength: 16});
    decipher.setAuthTag(envelope.authTag);
    plaintext = Buffer.concat([
      decipher.update(envelope.ciphertext),
      decipher.final()
    ]);
  } catch(cause) {
    throw new BedrockError(
      'Could not decrypt the bedrock config payload.',
      'OperationError', {
        httpStatusCode: 500,
        public: false,
        cause
      });
  }

  const actualSha256 = createHash('sha256').update(plaintext).digest('hex');
  if(actualSha256 !== envelope.plaintextSha256) {
    throw new BedrockError(
      'The decrypted bedrock config failed its integrity check.',
      'DataError', {
        httpStatusCode: 500,
        public: false,
        expectedSha256: envelope.plaintextSha256,
        actualSha256
      });
  }

  return plaintext;
}

function _decodeBase64(value) {
  // buffer accepts invalid characters, so require a canonical round trip
  const decoded = Buffer.from(value, 'base64');
  return decoded.length > 0 && decoded.toString('base64') === value ?
    decoded : null;
}

function _isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
