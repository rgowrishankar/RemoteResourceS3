/**
 * Copyright 2019 IBM Corp. All Rights Reserved.
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

const objectPath = require('object-path');
const request = require('request-promise-native');
const merge = require('deepmerge');
const xml2js = require('xml2js');
const clone = require('clone');
const loggerFactory = require('./bunyan-api');
const { BaseDownloadController } = require('@razee/razeedeploy-core');
const IamTokenGetter = require('./iam-token');

// we need to create only one instance of IamTokenGetter, so we are creating
// it here and not within the Download function. If we create it in the Download
// function we will end up creating a new IamTokenGetter for each event and
// call IAM multiple times to get token instead of just once per expiry interval
const iamTokenGetter = new IamTokenGetter();


module.exports = class RemoteResourceS3Controller extends BaseDownloadController {
  constructor(params) {
    params.finalizerString = params.finalizerString || 'children.downloads.deploy.razee.io';
    params.logger = params.logger || loggerFactory.createLogger('RemoteResourceS3Controller');
    super(params);
  }
  // ============ Download From Bucket ============

  async added() {
    let requests = objectPath.get(this.data, ['object', 'spec', 'requests'], []);
    let newRequests = [];
    for (let i = 0; i < requests.length; i++) {
      let r = requests[i];
      const url = new URL(objectPath.get(r, 'options.url'));
      if (url.pathname.endsWith('/')) { //This is an S3 bucket
        let additionalRequests = await this._getBucketObjectRequestList(r);
        newRequests = newRequests.concat(additionalRequests);
      } else {
        newRequests.push(r);
      }
    }
    objectPath.set(this.data, ['object', 'spec', 'requests'], newRequests);
    let result = await super.added();
    return result;
  }

  async download(reqOpt) {
    let hmac = objectPath.get(this.data, ['object', 'spec', 'auth', 'hmac']);
    let iam = objectPath.get(this.data, ['object', 'spec', 'auth', 'iam']);
    let options = {};
    if (hmac) {
      let { accessKeyId, secretAccessKey } = await this._fetchHmacSecrets(hmac);
      objectPath.set(options, 'aws.key', accessKeyId);
      objectPath.set(options, 'aws.secret', secretAccessKey);
    } else if (iam) {
      const bearerToken = await iamTokenGetter.fetchS3Token(iam, this.kubeResourceMeta, this.namespace);
      objectPath.set(options, 'headers.Authorization', `bearer ${bearerToken}`);
    }
    let opt = merge(reqOpt, options);
    this.log.debug(`Download ${opt.uri || opt.url}`);

    opt.simple = false;
    opt.resolveWithFullResponse = true;

    return await request(opt);
  }

  // ============ Bucket Specific Syntax ============

  async _fixUrl(url) {
    const u = new URL(url);
    if (u.hostname.startsWith('s3.')) { //The bucket name is part of the path
      let pathSegments = u.pathname.split('/');
      pathSegments.shift(); //Discard the leading slash
      u.pathname = pathSegments.shift();
      u.search = `prefix=${pathSegments.join('/')}`;
    } else { //The bucket name is part of the hostname
      let hostnameSegments = u.hostname.split('.');
      let bucket = hostnameSegments.shift();
      u.hostname = hostnameSegments.join('.');
      let prefix = u.pathname.slice(1, u.pathname.length);
      u.search = `prefix=${prefix}`;
      u.pathname = bucket;
    }
    if (u.pathname === '/') {
      this.log.error(`No bucket name found for ${url}`);
      return Promise.reject({ statusCode: 500, uri: url, message: `Error getting bucket name from ${url}` });
    }
    return u.toString();
  }

  async _getBucketObjectRequestList(bucketRequest) {
    const result = [];
    const bucketUrl = objectPath.get(bucketRequest, 'options.url', objectPath.get(bucketRequest, 'options.uri'));
    objectPath.del(bucketRequest, 'options.uri');
    const url = await this._fixUrl(bucketUrl);
    objectPath.set(bucketRequest, 'options.url', url);
    const objectListResponse = await this.download(bucketRequest.options);
    if (objectListResponse.statusCode >= 200 && objectListResponse.statusCode < 300) {
      this.log.debug(`Download ${objectListResponse.statusCode} ${url}`);
      const objectListString = objectListResponse.body;
      const parser = new xml2js.Parser();
      try {
        const objectList = await parser.parseStringPromise(objectListString);
        const xmlns = objectPath.get(objectList, 'ListBucketResult.$.xmlns');
        if (xmlns !== 'http://s3.amazonaws.com/doc/2006-03-01/') {
          this.log.warn(`Unexpected S3 bucket object list namespace of ${xmlns}.`);
        }
        let bucket = objectPath.get(objectList, 'ListBucketResult.Name');
        let objectsArray = objectPath.get(objectList, 'ListBucketResult.Contents', []);
        objectsArray.forEach((o) => {
          const objectKey = objectPath.get(o, 'Key.0');
          const reqClone = clone(bucketRequest);
          const newUrl = new URL(url);
          newUrl.pathname = `${bucket}/${objectKey}`;
          newUrl.searchParams.delete('prefix');
          objectPath.set(reqClone, 'options.url', newUrl.toString());
          result.push(reqClone);
        });
      } catch (err) {
        this.log.error(err, `Error getting bucket listing for ${url}`);
        return Promise.reject({ statusCode: 500, uri: url, message: `Error getting bucket listing for ${url}` });
      }
    } else {
      this.log.error(`Download failed: ${objectListResponse.statusCode} | ${url}`);
      return Promise.reject({ statusCode: objectListResponse.statusCode, uri: url });
    }
    if (result.length === 0) {
      this.log.error(`Error getting resources for ${url}, no resources found.`);
      return Promise.reject({ statusCode: 404, uri: url, message: `Error getting resources for ${url}, no resources found.` });
    }
    return result;
  }

  // ============ Fetch Secrets ============

  async _fetchHmacSecrets(hmac) {
    let akid;
    let akidAlpha1 = objectPath.get(hmac, 'access_key_id');
    let akidStr = objectPath.get(hmac, 'accessKeyId');
    let akidRef = objectPath.get(hmac, 'accessKeyIdRef');

    if (typeof akidAlpha1 == 'string') {
      akid = akidAlpha1;
    } else if (typeof akidStr == 'string') {
      akid = akidStr;
    } else if (typeof akidAlpha1 == 'object') {
      let secretName = objectPath.get(akidAlpha1, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(akidAlpha1, 'valueFrom.secretKeyRef.namespace', this.namespace);
      let secretKey = objectPath.get(akidAlpha1, 'valueFrom.secretKeyRef.key');
      akid = await this._getSecretData(secretName, secretKey, secretNamespace);
    } else if (typeof akidRef == 'object') {
      let secretName = objectPath.get(akidRef, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(akidRef, 'valueFrom.secretKeyRef.namespace', this.namespace);
      let secretKey = objectPath.get(akidRef, 'valueFrom.secretKeyRef.key');
      akid = await this._getSecretData(secretName, secretKey, secretNamespace);
    }
    if (!akid) {
      throw Error('Must have an access key id when using HMAC');
    }

    let sak;
    let sakAlpha1 = objectPath.get(hmac, 'secret_access_key');
    let sakStr = objectPath.get(hmac, 'secretAccessKey');
    let sakRef = objectPath.get(hmac, 'secretAccessKeyRef');

    if (typeof sakAlpha1 == 'string') {
      sak = sakAlpha1;
    } else if (typeof sakStr == 'string') {
      sak = sakStr;
    } else if (typeof sakAlpha1 == 'object') {
      let secretName = objectPath.get(sakAlpha1, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(sakAlpha1, 'valueFrom.secretKeyRef.namespace', this.namespace);
      let secretKey = objectPath.get(sakAlpha1, 'valueFrom.secretKeyRef.key');
      sak = await this._getSecretData(secretName, secretKey, secretNamespace);
    } else if (typeof sakRef == 'object') {
      let secretName = objectPath.get(sakRef, 'valueFrom.secretKeyRef.name');
      let secretNamespace = objectPath.get(sakRef, 'valueFrom.secretKeyRef.namespace', this.namespace);
      let secretKey = objectPath.get(sakRef, 'valueFrom.secretKeyRef.key');
      sak = await this._getSecretData(secretName, secretKey, secretNamespace);
    }
    if (!sak) {
      throw Error('Must have a secret access key when using HMAC');
    }

    return { accessKeyId: akid, secretAccessKey: sak };
  }

  async _getSecretData(name, key, ns) {
    let res = await this.kubeResourceMeta.request({ uri: `/api/v1/namespaces/${ns || this.namespace}/secrets/${name}`, json: true });
    let apiKey = Buffer.from(objectPath.get(res, ['data', key], ''), 'base64').toString();
    return apiKey;
  }


};
