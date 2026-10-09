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
import {
  decryptEnvelope, parseEnvelope
} from '@bedrock/config-yaml-aws/lib/envelope.js';
import {Buffer} from 'node:buffer';

const plaintext = new TextEncoder().encode('core:\n  workers: 1\n');
const key = new Uint8Array(32).fill(1);

describe('AWS config envelope', () => {
  it('parses and decrypts a version-1 envelope', () => {
    const envelope = parseEnvelope(_createEnvelope());

    envelope.encryptedDataKey.should.be.instanceOf(Uint8Array);
    decryptEnvelope({envelope, key}).should.deep.equal(plaintext);
  });

  it('rejects invalid JSON', () => {
    const error = _getError(() => parseEnvelope('{'));

    error.name.should.equal('SyntaxError');
  });

  it('rejects an unsupported envelope version', () => {
    const value = JSON.parse(_createEnvelope());
    value.version = 2;
    const error = _getError(() => parseEnvelope(JSON.stringify(value)));

    error.name.should.equal('NotSupportedError');
    error.details.actualVersion.should.equal(2);
  });

  it('identifies a missing envelope field', () => {
    const value = JSON.parse(_createEnvelope());
    delete value.authTag;
    const error = _getError(() => parseEnvelope(JSON.stringify(value)));

    error.name.should.equal('DataError');
    error.details.field.should.equal('authTag');
  });

  it('rejects an invalid binary field', () => {
    const value = JSON.parse(_createEnvelope());
    value.iv = 'not-base64';
    const error = _getError(() => parseEnvelope(JSON.stringify(value)));

    error.name.should.equal('DataError');
    error.details.field.should.equal('iv');
  });

  it('rejects characters ignored by the base64 decoder', () => {
    const value = JSON.parse(_createEnvelope());
    value.iv += '!';
    const error = _getError(() => parseEnvelope(JSON.stringify(value)));

    error.details.field.should.equal('iv');
  });

  it('rejects invalid hexadecimal hash characters', () => {
    const value = JSON.parse(_createEnvelope());
    value.plaintextSha256 = `${'0'.repeat(63)}x`;
    const error = _getError(() => parseEnvelope(JSON.stringify(value)));

    error.name.should.equal('DataError');
  });

  it('rejects an invalid data key', () => {
    const envelope = parseEnvelope(_createEnvelope());
    const error = _getError(() => decryptEnvelope({
      envelope, key: new Uint8Array(31)
    }));

    error.name.should.equal('DataError');
    error.details.actualBytes.should.equal(31);
  });

  it('rejects an unauthenticated ciphertext', () => {
    const envelope = parseEnvelope(_createEnvelope());
    envelope.ciphertext[0] ^= 1;
    const error = _getError(() => decryptEnvelope({envelope, key}));

    error.name.should.equal('OperationError');
  });

  it('rejects a plaintext hash mismatch', () => {
    const value = JSON.parse(_createEnvelope());
    value.plaintextSha256 = '0'.repeat(64);
    const envelope = parseEnvelope(JSON.stringify(value));
    const error = _getError(() => decryptEnvelope({envelope, key}));

    error.name.should.equal('DataError');
    error.details.actualSha256.should.equal(
      createHash('sha256').update(plaintext).digest('hex'));
  });
});

function _createEnvelope() {
  const iv = new Uint8Array(12).fill(2);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  return JSON.stringify({
    version: 1,
    format: 'yaml',
    kmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/test',
    encryptedDataKey: Buffer.from('encrypted key').toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    plaintextSha256: createHash('sha256').update(plaintext).digest('hex')
  });
}

function _getError(fn) {
  try {
    fn();
  } catch(error) {
    return error;
  }
  throw new Error('Expected operation to fail.');
}
