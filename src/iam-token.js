/**
 * Copyright 2021 IBM Corp. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const axios = require('axios');
const objectPath = require('object-path');
const hash = require('object-hash');
const sleep = require('sleep-promise');

let waitingForToken = false

module.exports = class IamTokenGetter {
  constructor() {
      this.s3TokenCache = {}
      this.log = require('./bunyan-api').createLogger('IamTokenGetter');

  }
    async fetchS3Token(iam, kubeResourceMeta, namespace) {
    let apiKey;
    let apiKeyAlpha1 = objectPath.get(iam, 'api_key');
    let apiKeyStr = objectPath.get(iam, 'apiKey');
    let apiKeyRef = objectPath.get(iam, 'apiKeyRef');

    if (typeof apiKeyAlpha1 == 'string') {
      apiKey = apiKeyAlpha1;
    } else if (typeof apiKeyStr == 'string') {
      apiKey = apiKeyStr;
    } else if (typeof apiKeyAlpha1 == 'object') {
      let secretName = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.namespace', namespace);
      let secretKey = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.key');
        apiKey = await this._getSecretData(secretName, secretKey, secretNamespace, kubeResourceMeta, namespace);
    } else if (typeof apiKeyRef == 'object') {
      let secretName = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.namespace', namespace);
      let secretKey = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.key');
        apiKey = await this._getSecretData(secretName, secretKey, secretNamespace, kubeResourceMeta, namespace);
    }
    if (!apiKey) {
      return Promise.reject('Failed to find valid apikey to authenticate against iam');
    }

    let res = await this._requestToken(iam, apiKey);
    return res.access_token;
  }


  async _requestToken(iam, apiKey) {
    let token;

    const apiKeyHash = hash(apiKey, { algorithm: 'shake256' });
      if (token === undefined && objectPath.has(this.s3TokenCache, [apiKeyHash])) {
      // fetch cached token
        token = objectPath.get(this.s3TokenCache, [apiKeyHash]);
        this.log.info(`MASCD got the cached token`);
    }
    if (token !== undefined) {
      const expires = objectPath.get(token, 'expiration', 0); // expiration: time since epoch in seconds
      // re-use cached token as long as we are more than 2 minutes away from expiring.
      if (Date.now() < (expires - 120) * 1000) {
        this.log.info(`MASCD cached token has not expired, returning it`);
        return token;
      } else {
        this.log.info(`MASCD cached token expired getting new one`);
      }
    }

    if (waitingForToken === true) {
      this.log.info(`MASCD waiting for different event to get a token`);
      while (waitingForToken === true) {
        this.log.info(`MASCD going to sleep`);
        await sleep(2000);
        this.log.info(`MASCD done with sleep`);
      }
      token = objectPath.get(this.s3TokenCache, [apiKeyHash]);
      const expires = objectPath.get(token, 'expiration', 0);
      this.log.info(`MASCD token expires ${expires}`)
      if (Date.now() < (expires - 120) * 1000) {
          this.log.info(`MASCD cached token got by other event has not expired, returning it`);
          return token;
      } else {
          this.log.info(`MASCD cached token got by other event expired getting new one`);
      }

    } else {
        this.log.info(`MASCD going to get the new token, setting waiting for token to true`)
        waitingForToken = true
    }

    try {
      let res = await axios({
        method: 'post',
        url: iam.url, // 'https://iam.cloud.ibm.com/identity/token',
        params: {
          'grant_type': iam.grantType || iam.grant_type, // 'urn:ibm:params:oauth:grant-type:apikey',
          'apikey': apiKey
        },
        // data: `grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=${apiKey}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 60000
      });
      token = res.data;
      try {
        objectPath.set(this.s3TokenCache, [apiKeyHash], token);
      } catch (fe) {
        return Promise.reject(`failed to cache s3Token to disk at path ${tokenCacheFile}`, fe);
      }
      waitingForToken = false;
      this.log.info(`MASCD returning new token`);
      return token;
    } catch (err) {
      const error = Buffer.isBuffer(err) ? err.toString('utf8') : err;
      return Promise.reject(error.toJSON());
    }
  }

  async _getSecretData(name, key, ns, kubeResourceMeta, namespace) {
    let res = await kubeResourceMeta.request({ uri: `/api/v1/namespaces/${ns || namespace}/secrets/${name}`, json: true });
    let apiKey = Buffer.from(objectPath.get(res, ['data', key], ''), 'base64').toString();
    return apiKey;
  }

  async gotNewToken() {
  }

};
