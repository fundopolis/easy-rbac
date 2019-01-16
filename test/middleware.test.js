'use strict';

const mock = require('sinon-express-mock');
const sinon = require('sinon');
const RBAC = require('../lib/rbac');
let data = require('./data');

const assert = require('assert');
const {shouldBeAllowed, shouldNotBeAllowed, catchError} = require('./utils');

describe('RBAC middleware', function() {
  it('should reject if no roles object', () => {
    assert.throws(
      () => {
        rbac = RBAC.main();
      },
      TypeError
    );
  });

  it('should throw error if no roles object', () => {
    assert.throws(
      () => {
        rbac = RBAC.main('hello');
      },
      TypeError
    );
  });

  it('should return middleware function', () => {
    const rbac = RBAC.main(data.all);
    assert.equal(typeof rbac, 'function');
  });

  it('should put rbac into request', () => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(), res = mock.mockRes(), next = function(){};
    rbac(req, res, next);
    assert.notEqual(req.rbac, undefined);
  });

  describe('enforce can parameter constraints', function() {
    it('should should reject undefined operation', () => {
      assert.throws(
        () => {
          RBAC.can();
        },
        TypeError
      );
    });
    it('should accept operation string', () => {
      assert.doesNotThrow(
        () => {
          RBAC.can('role', 'operation');
        }
      );
    });
  });

  it('should allow static role', done => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(), 
      res = mock.mockRes(), 
      next = function(){};
    rbac(req, res, next);
    const can = RBAC.can('user', 'account:add');
    can(req, res, done);
  });

  it('should allow role returned by function', done => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can(function(){return 'user'}, 'account:add');
    can(req, res, done);
  });

  it('should allow role returned by function with request', done => {
    const rbac = RBAC.main(data.all);
    let request = {
      role: 'user'
    };
    let req = mock.mockReq(request),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can(function(req,res){return req.role}, 'account:add');
    can(req, res, done);
  });

  it('should return 403 on unallowed operation', () => {
    const rbac = RBAC.main(data.all);
    let req = mock.mockReq(),
      res = mock.mockRes();
    const next = function(){};
    rbac(req, res, next);
    const can = RBAC.can('user', 'foo_op');
    can(req, res, next);
    assert(res.sendStatus.called);
    assert(res.sendStatus.calledWith(403));
  });
  

  // it('should reject if function throws', function (done) {
  //   (RBAC.main(async () => {
  //     throw new Error();
  //   }))._init
  //     .then(function () {
  //       done(new Error('Should not succeed'));
  //     })
  //     .catch(function () {
  //       done();
  //     });
  // });

  // it('should reject if function returns non object', function (done) {
  //   (RBAC.main(async () => 1))
  //     ._init
  //     .then(function () {
  //       done(new Error('Should not succeed'));
  //     })
  //     .catch(function () {
  //       done();
  //     });
  // });

  // it('mw should reject if roles[$i].inherits is not an array', function (done) {
  //   (RBAC.main(async () => ({
  //     hello: {
  //       can: ['hel'],
  //       inherits: 1
  //     }
  //   })))
  //     ._init
  //     .then(function () {
  //       done(new Error('Should not succeed'));
  //     })
  //     .catch(function () {
  //       done();
  //     });
  // });

  // it('should reject if roles[$i].inherits[$i2] is not a string', function (done) {
  //   (new RBAC(async () => ({
  //     hello: {
  //       can: ['hel'],
  //       inherits: [1]
  //     }
  //   })))
  //     ._init
  //     .then(function () {
  //       done(new Error('Should not succeed'));
  //     })
  //     .catch(function () {
  //       done();
  //     });
  // });

  // it('should reject if roles[$i].inherits[$i2] is not a defined role', function (done) {
  //   (new RBAC(async () => ({
  //       hello: {
  //         can: ['hel'],
  //         inherits: ['what']
  //       }
  //   })))
  //     ._init
  //     .then(function () {
  //       done(new Error('Should not succeed'));
  //     })
  //     .catch(function () {
  //       done();
  //     });
  // });

  // it('should resolve if function returns correct object', function (done) {
  //   (new RBAC(async () => data.all))
  //     ._init
  //     .then(function () {
  //       done();
  //     })
  //     .catch(function () {
  //       done(new Error('Should not reject'));
  //     });
  // });

  // describe('resolve current role operations', function () {
  //   it('should respect operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'post:add')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should reject undefined operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'post:what')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });
  //   it('should reject undefined users', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('what', 'post:add')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should reject function operations with no operands', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'post:save')
  //       .then(shouldNotBeAllowed(done))
  //       .catch(err => done());
  //   });

  //   it('should reject function operations with rejectable values', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'post:save', {ownerId: 1, postId: 2})
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should allow function operations with correct values', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'post:save', {ownerId: 1, postId: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });

  //   it('should reject conditional glob operations with no params', done => {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'user:save')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should reject conditional glob operations with wrong params', done => {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'user:save', {userId: 1, id: 2})
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should allow glob operations with correct params', done => {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'user:save', {userId: 1, id: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });

  //   it('should prioritize non glob operations', done => {
  //     (new RBAC(async () => data.all))
  //       .can('user', 'user:create')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  // });

  // describe('parent role operations', function () {
  //   it('should respect allowed operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'account:add')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should reject undefined operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'post:what')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should respect allowed glob operations', done => {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'account:whatever')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should handle overwritten glob operations', done => {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'user:save', {regionId: 1, userRegionId: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  // });
  // describe('parents parent role operations', function () {
  //   it('should respect allowed operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('admin', 'account:add')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should reject undefined operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('admin', 'post:what')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should respect glob operations', done => {
  //     (new RBAC(async () => data.all))
  //       .can('admin', 'user:what')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  // });

  // describe('parent role operations with callback', function () {
  //   it('should respect allowed operations', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'post:create', {postId: 1, ownerId: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should reject not allowed operation', function (done) {
  //     (new RBAC(async () => data.all))
  //       .can('manager', 'post:create', {postId: 1, ownerId: 2})
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });
  // });

  // describe('array of roles', () => {
  //   it('should not allow if empty array of roles', done => {
  //     (new RBAC(async () => data.all))
  //       .can([], 'post:what')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });
  //   it('should not allow if none of the roles is allowed', done => {
  //     (new RBAC(async () => data.all))
  //       .can(['user', 'manager'], 'rule the world')
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });
  //   it('should allow if one of the roles is allowed', done => {
  //     (new RBAC(async () => data.all))
  //       .can(['user', 'admin'], 'post:delete')
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should allow if one of the roles is allowed', done => {
  //     (new RBAC(async () => data.all))
  //       .can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  //   it('should not allow if none of the roles is allowed', done => {
  //     (new RBAC(async () => data.all))
  //       .can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 2})
  //       .catch(catchError(done))
  //       .then(shouldNotBeAllowed(done));
  //   });

  //   it('should allow if one of the roles is allowed through glob', done => {
  //     (new RBAC(async () => data.all))
  //       .can(['user', 'manager'], 'user:save', {regionId: 1, userRegionId: 1})
  //       .catch(catchError(done))
  //       .then(shouldBeAllowed(done));
  //   });
  // });
  
});