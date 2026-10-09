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

import {config} from '@bedrock/core';

config['config-yaml-aws'] = {
  enabled: process.env.BEDROCK_CONFIG_YAML_AWS_ENABLED === 'true',
  environment:
    process.env.BEDROCK_CONFIG_YAML_AWS_ENVIRONMENT ?? null,
  maxWaitMs: 300000,
  secretIdTag: 'BedrockConfigSecretId'
};
