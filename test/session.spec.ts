'use strict';

import { expect } from 'chai';
import { Hashing } from '../src/hashing';
import { Session } from '../src/session';

let previous;
const session = new Session(new Hashing({}));
const testToken = {
  _id: 'colinskow',
  roles: ['admin', 'user'],
  key: 'test123',
  issued: Date.now(),
  expires: Date.now() + 50000,
  password_scheme: 'pbkdf2',
  iterations: 10,
  salt: '991bc3c09ff7322f7f1361e383a9d9f8',
  derived_key: 'e04e30ee0ef31d541f1fb731c9631a9f48fa5196'
};
const testToken600k = {
  _id: 'colinskow',
  roles: ['admin', 'user'],
  key: 'test123',
  issued: Date.now(),
  expires: Date.now() + 50000,
  password_scheme: 'pbkdf2',
  iterations: 600000,
  salt: 'a0884aaf0a8ae822a1699b094c8bddfb',
  derived_key: '1edebc836406860a6aff57ddee1d43aa3dd243b2e11aa152a01cb782b440acd5'
};
const badToken = {
  ...testToken,
  salt: 'salt',
  derived_key: 'key'
};
describe('Session', async function () {
  previous = Promise.resolve();

  it('should confirm a token and return it if valid', function (done) {
    previous.then(function () {
      return session
        .confirmToken(testToken, 'pass123')
        .then(function (result) {
          console.log('confirmed valid token.');
          done();
        })
        .catch(function (err) {
          console.log('confirmToken - got err: ', err);
          done(err);
        });
    });
  });

  it('should reject a bad token', function (done) {
    previous.then(function () {
      return session.confirmToken(badToken, 'pass123').catch(function (err) {
        console.log('rejected invalid token');
        expect(err.message).to.equal('invalid token');
        done();
      });
    });
  });

  it('should reject a wrong password', function (done) {
    previous.then(function () {
      return session.confirmToken(testToken, 'wrongpass').catch(function (err) {
        console.log('rejected invalid token');
        expect(err.message).to.equal('invalid token');
        done();
      });
    });
  });

  it('should confirm a token with 600000 iterations', function (done) {
    previous.then(function () {
      return session
        .confirmToken(testToken600k, 'pass123')
        .then(function (result) {
          console.log('confirmed valid token.');
          done();
        })
        .catch(function (err) {
          console.log('confirmToken - got err: ', err);
          done(err);
        });
    });
  });
});
