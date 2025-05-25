import pwdModule from '@sl-nx/couch-pwd';
import { Config } from './types/config';
import { HashResult, LocalHashObj } from './types/typings';
import { URLSafeUUID } from './util';

const pwdOld = new pwdModule();
const pwdNew = new pwdModule(600000, 32, 16, 'hex', 'sha256');

export function hashCouchPassword(password: string, iterations: number): Promise<HashResult> {
  return new Promise(function (resolve, reject) {
    const pwd = iterations < 600000 ? pwdOld : pwdNew;
    pwd.hash(password, function (err, salt, hash) {
      if (err) {
        return reject(err);
      }
      return resolve({
        salt: salt,
        derived_key: hash
      });
    });
  });
}
export class Hashing {
  hashers = [];
  times: number[] = [];
  dummyHashObject: LocalHashObj = { iterations: 10 };

  constructor(config: Partial<Config>) {
    const iterationPairs = config.security?.iterations;
    if (iterationPairs) {
      for (const pair of config.security.iterations) {
        this.times.push(pair[0]);
        this.hashers.push(new pwdModule(pair[1]));
      }
    }
    this.hashUserPassword(URLSafeUUID()).then(dummy => {
      this.dummyHashObject = dummy;
    });
  }

  private getHasherForTimestamp(ts: number = undefined, iterations: number = 600000): pwdModule {
    let ret = iterations < 600000 ? pwdOld : pwdNew;
    if (this.times.length === 0 || ts === undefined) {
      return ret;
    }
    for (let idx = 0; idx < this.times.length; idx++) {
      if (ts > this.times[idx]) {
        ret = this.hashers[idx];
      } else {
        break;
      }
    }
    return ret;
  }

  hashUserPassword(pw: string): Promise<HashResult> {
    const t = new Date().valueOf();
    return new Promise((resolve, reject) => {
      this.getHasherForTimestamp(t).hash(pw, (err, salt, hash) => {
        if (err) {
          return reject(err);
        }
        return resolve({
          salt: salt,
          derived_key: hash
        });
      });
    }).then((hr: HashResult) => {
      hr.created = t;
      return hr;
    });
  }

  verifyUserPassword(hashObj: HashResult, pw: string): Promise<boolean> {
    const salt = hashObj.salt ?? this.dummyHashObject.salt;
    const derived_key = hashObj.derived_key ?? this.dummyHashObject.derived_key;
    let created = hashObj.created;
    if (!hashObj.salt && !hashObj.derived_key) {
      created = this.dummyHashObject.created;
    }

    return new Promise((resolve, reject) => {
      const hasher = this.getHasherForTimestamp(created, hashObj?.iterations);
      hasher.hash(pw, salt, (err, hash) => {
        if (err) {
          return reject(err);
        } else if (hash !== derived_key) {
          return reject(false);
        } else {
          return resolve(true);
        }
      });
    });
  }
}
