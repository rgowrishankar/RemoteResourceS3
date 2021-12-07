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


module.exports = class IamTokenGetter {
  constructor() {
    this.s3TokenCache = {};
    this.log = require('./bunyan-api').createLogger('IamTokenGetter');
  }
  async fetchS3Token(iam, kubeResourceMeta, namespace) {
    let apiKey;
    const apiKeyAlpha1 = objectPath.get(iam, 'api_key');
    const apiKeyStr = objectPath.get(iam, 'apiKey');
    const apiKeyRef = objectPath.get(iam, 'apiKeyRef');

    if (typeof apiKeyAlpha1 == 'string') {
      apiKey = apiKeyAlpha1;
    } else if (typeof apiKeyStr == 'string') {
      apiKey = apiKeyStr;
    } else if (typeof apiKeyAlpha1 == 'object') {
      const secretName = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.name');
      const secretNamespace = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.namespace', namespace);
      const secretKey = objectPath.get(apiKeyAlpha1, 'valueFrom.secretKeyRef.key');
      apiKey = await this._getSecretData(secretName, secretKey, secretNamespace, kubeResourceMeta, namespace);
    } else if (typeof apiKeyRef == 'object') {
      const secretName = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.name');
      const secretNamespace = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.namespace', namespace);
      const secretKey = objectPath.get(apiKeyRef, 'valueFrom.secretKeyRef.key');
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
    // Check if the cache has the token. If it does have it, copy it into token
    // for further processing
    if (objectPath.has(this.s3TokenCache, [apiKeyHash])) {
      // fetch cached token
      token = objectPath.get(this.s3TokenCache, [apiKeyHash]);
    }

    // if we are able to fetch the token from the cache and it is not a Promise,
    // then we need to check the expiry. If it is not expiring in the next 120 s
    // return the token
    if (!(token instanceof Promise)) {
      if (token !== undefined) {
        const expires = objectPath.get(token, 'expiration', 0); // expiration: time since epoch in seconds
        // re-use cached token as long as we are more than 2 minutes away from expiring.
        if (Date.now() < (expires - 120) * 1000) {
          return token;
        } else {
          this.log.info(`IAM token is about to expire ${expires}`);
        }
      }

      // if we get to this point the token is either undefined or it is stale data.
      // either ways we need to connect to iam auth and get a new token
      // create an async function that will wait for _getToken to return a token.
      // since we are not using await, the control will return immediately and the
      // return value of the tokenFunction is going to be a promise.
      // we are going to cache this promise into the s3TokenCache and
      // wait for it.
      try {
        token = this._getToken(iam, apiKeyHash, apiKey);
        objectPath.set(this.s3TokenCache, [apiKeyHash], token);
      } catch (error) {
        objectPath.del(this.s3TokenCache, [apiKeyHash]); // Clear cache for future retry.
        return Promise.reject(error);
      }
    }

    // at this point token is either data, or Promise (either created in the else case above
    // or already created by a different event)
    if (token instanceof Promise) {
      // if the token is a Promise, wait for it to be completed. Once completed, get
      // the data from the cache and return it.
      try {
        token = await token;
        objectPath.set(this.s3TokenCache, [apiKeyHash], token);
        return token;
      } catch(error) {
        return Promise.reject('failed to get the new token:', error);
      }
    } else if (token === undefined) {
      objectPath.del(this.s3TokenCache, [apiKeyHash]); // Clear cache for future retry.
      return Promise.reject('Something went wrong in trying to get the iam token. This code path should never get triggered');
    } else {
      // assume that it is a token
      return token;
    }
  }

  async _getToken(iam, apiKeyHash, apiKey) {
    try {
      const res = await axios({
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
      this.log.info('Got a new token from IAM, setting it in the local cache');
      return token;
    } catch (err) {
      const error = Buffer.isBuffer(err) ? err.toString('utf8') : err;
      objectPath.del(this.s3TokenCache, [apiKeyHash]); // Clear cache for future retry.
      return Promise.reject(error);
    }

  }

  async _getSecretData(name, key, ns, kubeResourceMeta, namespace) {
    const res = await kubeResourceMeta.request({ uri: `/api/v1/namespaces/${ns || namespace}/secrets/${name}`, json: true });
    const apiKey = Buffer.from(objectPath.get(res, ['data', key], ''), 'base64').toString();
    return apiKey;
  }
};
