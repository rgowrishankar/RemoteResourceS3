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
const fs = require('fs-extra')

let waitingForToken = new Map()

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

    console.log(`MASCD entering _requestToken`)

    const apiKeyHash = hash(apiKey, { algorithm: 'shake256' });
    if (token === undefined && objectPath.has(this.s3TokenCache, [apiKeyHash])) {
      // fetch cached token
        token = objectPath.get(this.s3TokenCache, [apiKeyHash]);
        this.log.info(`MASCD got the cached token`);
    } else {
        console.log(`MASCD no cached token need to get new token`)
    }

    if (token !== undefined && !(token instanceof Promise)) {
      this.log.info(`MASCD token is not undefined and not a promise, `)
      const expires = objectPath.get(token, 'expiration', 0); // expiration: time since epoch in seconds
      // re-use cached token as long as we are more than 2 minutes away from expiring.
      if (Date.now() < (expires - 120) * 1000) {
        this.log.info(`MASCD cached token has not expired, returning it`);
        return token;
      } else {
        this.log.info(`MASCD cached token expired getting new one`);
      }
    } else if (token === undefined) {
        this.log.info(`MASCD token is undefined, setting it to async promise argh`)
        let tokenFunction = async (iam, apiKeyHash, apiKey) => { this.log.info(`MASCD within the async fn`); ret = await this._getToken(iam, apiKeyHash, apiKey); return ret;};
        this.log.info(`MASCD going to call the token function`)
        token = tokenFunction(iam, apiKeyHash, apiKey)
        this.log.info(`MASCD called the token function`)
        objectPath.set(this.s3TokenCache, [apiKeyHash], token);
        this.log.info(`MASCD type of token ${typeof(token)}`)
    }

    if (token instanceof Promise) {
        this.log.info(`MASCD type of token is promise, going to try to wait for it`)
        try {
          await token
          this.log.info(`MASCD done waiting for token, returning token cache ${token} ${objectPath.get(this.s3TokenCache, [apiKeyHash])}`)
          return objectPath.get(this.s3TokenCache, [apiKeyHash]);
        } catch(error) {
            Promise.reject(`failed to get the new token:`, error);
        }
    } else if (token === undefined) {
        this.log.info(`MASCD token is not Promise and is undefined. why? going to await on getToken`)
        token = await this._getToken(iam, apiKeyHash)
        objectPath.set(this.s3TokenCache, [apiKeyHash], token)
        return token
    } else {
        this.log.info(`MASCD end of function, returning token`)
        objectPath.set(this.s3TokenCache, [apiKeyHash], token);
        return token
    }
  }

  async _getToken(iam, apiKeyHash, apiKey) {
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
      let token = res.data;
      objectPath.set(this.s3TokenCache, [apiKeyHash], token);
      let tokenCacheFile = `./download-cache/s3token-cache/${apiKeyHash}.json`;
      fs.outputJsonSync(tokenCacheFile, token);

      this.log.info(`MASCD returning new token in _getToken`);
      return token;
    } catch (err) {
      const error = Buffer.isBuffer(err) ? err.toString('utf8') : err;
      this.log.info(`error in getting iam ${error}`)
      return Promise.reject(error);
    }

  }

  async _getSecretData(name, key, ns, kubeResourceMeta, namespace) {
    let res = await kubeResourceMeta.request({ uri: `/api/v1/namespaces/${ns || namespace}/secrets/${name}`, json: true });
    let apiKey = Buffer.from(objectPath.get(res, ['data', key], ''), 'base64').toString();
    return apiKey;
  }
};
