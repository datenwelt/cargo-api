/* eslint-disable no-invalid-this,consistent-return,handle-callback-err,max-params,no-unused-vars */
const describe = require('mocha').describe;
const before = require('mocha').before;
const after = require('mocha').after;
const beforeEach = require('mocha').beforeEach;
const afterEach = require('mocha').afterEach;
const it = require("mocha").it;
const assert = require('chai').assert;
const sinon = require('sinon');

const TestConfig = require('../test-utils/test-config');
const TestServer = require('../test-utils/test-server');
const RSA = require('../../src/rsa');

const crypto = require('crypto');
const bluebird = require('bluebird');
const JWT = bluebird.promisifyAll(require('jsonwebtoken'));
const moment = require('moment');
const superagent = require('superagent');
const util = require('util');

const Checks = require('../../src/checks');
const Router = require('../../src/router');
const Server = require('../../src/server');

let config = null;
let app = null;
let rsa = null;

function suppressErrorLog(err, req, res, next) {
	if (err.name !== 'HttpError') console.log(err);
	if (!res.headersSent) res.end();
}

async function expectErrorResponse(code, error, xhrPromise) {
	try {
		await xhrPromise;
	} catch (err) {
		assert.property(err, 'response');
		const response = err.response;
		assert.equal(response.status, code, "Unexpected status code");
		assert.equal(response.header['x-error'], error, "Unexpected error header");
		return;
	}
	throw new Error('XMLHttpRequest was successful but should have failed.');
}


async function createValidSession(username, rsaPrivateKey) {
	// Create a session id.
	let hash = crypto.createHash('SHA1');
	hash.update(new Date().getTime().toString());
	hash.update(crypto.randomBytes(16));
	const sessionId = hash.digest('hex');
	const iat = moment();
	const exp = iat.add(48, 'h');
	const token = await
		JWT.signAsync({
			sess: sessionId,
			iat: iat.unix(),
			exp: exp.unix(),
			usr: {id: 1, nam: username}
		}, rsaPrivateKey, {algorithm: 'RS256'});
	return token;
}

async function createExpiredSession(username, rsaPrivateKey) {
	// Create a session id.
	let hash = crypto.createHash('SHA1');
	hash.update(new Date().getTime().toString());
	hash.update(crypto.randomBytes(16));
	const sessionId = hash.digest('hex');
	const iat = moment().subtract(49, 'h');
	const exp = iat.add(48, 'h');
	const token = await JWT.signAsync({
		sess: sessionId,
		iat: iat.unix(),
		exp: exp.unix(),
		usr: {id: 1, nam: username}
	}, rsaPrivateKey, {algorithm: 'RS256'});
	return token;
}

describe('router.js', function () {
	
	before(async function () {
		config = await TestConfig.get();
		app = await TestServer.start();
		rsa = await RSA.init(config.rsa);
	});
	
	beforeEach(async function () {
		app = await TestServer.start();
	});
	
	afterEach(function (done) {
		if (!app) done();
		app.server.close(done);
		app = null;
	});
	
	describe('static requireSessionToken()', function () {
		
		it('responds with 200 if session token is valid', async function () {
			let sessionToken = await createValidSession('testman', rsa.rsaPrivateKey);
			let requireSessionToken = Router.requireSessionToken(rsa.rsaPublicKey);
			let spy = sinon.spy(requireSessionToken);
			app.use('/', spy);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
			assert.isTrue(spy.called, "Router.checkSessionToken() has been called");
		});
		
		it('responds with 410 if session token is expired', async function () {
			let sessionToken = await createExpiredSession('testman', rsa.rsaPrivateKey);
			let requireSessionToken = Router.requireSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(requireSessionToken);
			app.use('/', spy1);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			try {
				let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 410);
				assert.isTrue(spy1.called, "Router.requireSessionToken() has been called");
			}
		});
		
		it('responds with 401 if session token is missing', async function () {
			let requireSessionToken = Router.requireSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(requireSessionToken);
			app.use('/', spy1);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			try {
				await superagent.get(app.uri.toString());
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 401);
				assert.isTrue(spy1.called, "Router.checkSessionToken() has been called");
			}
		});
		
		it('responds with 403 if session token is invalid', async function () {
			let sessionToken = "YXXXXXXZ";
			let requiresSessionToken = Router.requireSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(requiresSessionToken);
			app.use('/', spy1);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			try {
				let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 403);
				assert.isTrue(spy1.called, "Router.checkSessionToken() has been called");
			}
		});
		
	});
	
	describe('static checkBodyField()', function () {
		
		it('responds with 400/ERR_BODY_TEST_FIELD_MISSING when testField is not present in request', async function () {
			let checkBodyField = Router.checkBodyField('testField', (value) => {
				Checks.optional(false, value);
				return value;
			});
			let spy = sinon.spy(checkBodyField);
			app.post('/', spy);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			app.use(function (err, req, res, next) {
				if (!res.headersSent) res.end();
			});
			try {
				await superagent.post(app.uri.toString());
			} catch (err) {
				assert.isTrue(spy.called, "Router.checkBodyField() has been called");
				assert.property(err, 'response');
				assert.strictEqual(err.response.statusCode, 400);
				assert.strictEqual(err.response.get('X-Error'), 'ERR_BODY_TEST_FIELD_MISSING');
				return;
			}
			assert.fail(true, false, 'API call succeeded unexpectedly.');
		});
		
		it('passes when testField is optional and missing in request', async function () {
			let checkBodyField = Router.checkBodyField('testField', (value) => value, {optional: true});
			let spy = sinon.spy(checkBodyField);
			app.post('/', spy);
			app.post('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			await superagent.post(app.uri.toString()).send({});
			assert.isTrue(spy.called, "Router.checkBodyField() has been called");
		});
		
		
		it('Checks.cast() is called when testField is cast', async function () {
			let checkBodyField = Router.checkBodyField('testField', (value) => Checks.cast('number', value));
			let spy = sinon.spy(Checks, 'cast');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Router.checkBodyField() has been called");
			} finally {
				spy.restore();
			}
		});
		
		it('Checks.type() is called when testField is type-tested', async function () {
			let checkBodyField = Router.checkBodyField('testField', (value) => {
				return Checks.type('string', value)
			});
			let spy = sinon.spy(Checks, 'type');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Check.type() has been called");
			} finally {
				spy.restore();
			}
		});
		
		it('Checks.minLength() is called', async function () {
			let checkBodyField = Router.checkBodyField('testField',
				(value) => {
					return Checks.minLength(2, value)
				});
			let spy = sinon.spy(Checks, 'minLength');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Check.minLength() has been called");
			} finally {
				spy.restore();
			}
		});
		
		it('Checks.maxLength() is called', async function () {
			let checkBodyField = Router.checkBodyField('testField', (value) => Checks.maxLength(12, value));
			let spy = sinon.spy(Checks, 'maxLength');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Check.maxLength() has been called");
			} finally {
				spy.restore();
			}
		});
		
		it('Checks.match() is called', async function () {
			let checkBodyField = Router.checkBodyField('testField',
				(value) => {
					return Checks.match(/^1023$/, value)
				});
			let spy = sinon.spy(Checks, 'match');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Check.match() has been called");
			} finally {
				spy.restore();
			}
		});
		
		it('Checks.notBlank() is called', async function () {
			let checkBodyField = Router.checkBodyField('testField',
				(value) => {
					return Checks.notBlank(value)
				});
			let spy = sinon.spy(Checks, 'notBlank');
			app.post('/', checkBodyField);
			app.post('/', function (req, res, next) {
				if (!res.headersSent) res.sendStatus(200);
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.post(app.uri.toString()).send({testField: '1023'});
				assert.isTrue(spy.called, "Check.notBlank() has been called");
			} finally {
				spy.restore();
			}
		});
	});
	
	describe('static checkRequestHeader()', function () {
		
		let spy = null;
		
		afterEach(function () {
			if (spy) spy.restore();
			spy = null;
		});
		
		it('passes with non-optional valid input values', async function () {
			let checkRequestHeader = Router.checkRequestHeader('x-test-header', (value) => {
				Checks.optional(false, value);
				return value;
			});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkRequestHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString()).set('x-test-header', 'XXXXX');
				assert.isTrue(spy.called, 'Header check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes with optional but missing input values', async function () {
			let checkRequestHeader = Router.checkRequestHeader('x-test-header', (value) => {
				return value;
			}, {optional: true});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkRequestHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString());
				assert.isTrue(spy.called, 'Query check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('responds with status 400 and ERR_HEADER_X_TEST_HEADER_MISSING if non-optional value misses', async function () {
			let checkRequestHeader = Router.checkRequestHeader('x-test-header', (value) => value);
			app.get('/', checkRequestHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			await expectErrorResponse(400, 'ERR_HEADER_X_TEST_HEADER_MISSING',
				superagent.get(app.uri.toString()));
		});
	});
	
	describe('static checkQueryParam()', function () {
		
		let spy = null;
		
		afterEach(function () {
			if (spy) spy.restore();
			spy = null;
		});
		
		it('passes with non-optional valid input values', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => {
				Checks.optional(false, value);
				return value;
			});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString() + "?testparam=xxx");
				assert.isTrue(spy.called, 'Query check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes with optional but missing input values', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => {
				return value;
			}, {optional: true});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString());
				assert.isTrue(spy.called, 'Query check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('responds with status 400 and ERR_QUERY_TESTPARAM_MISSING if non-optional value misses', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => value);
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			await expectErrorResponse(400, 'ERR_QUERY_TESTPARAM_MISSING',
				superagent.get(app.uri.toString()));
		});
	});
	
	describe('static checkQueryParam()', function () {
		
		let spy = null;
		
		afterEach(function () {
			if (spy) spy.restore();
			spy = null;
		});
		
		it('passes with non-optional valid input values', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => {
				Checks.optional(false, value);
				return value;
			});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString() + "?testparam=xxx");
				assert.isTrue(spy.called, 'Query check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes with optional but missing input values', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => {
				return value;
			}, {optional: true});
			spy = sinon.spy(Checks, 'optional');
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString());
				assert.isTrue(spy.called, 'Query check predicate has been called.');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('responds with status 400 and ERR_QUERY_TESTPARAM_MISSING if non-optional value misses', async function () {
			let checkQueryParam = Router.checkQueryParameter('testparam', (value) => value);
			app.get('/', checkQueryParam);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			await expectErrorResponse(400, 'ERR_QUERY_TESTPARAM_MISSING',
				superagent.get(app.uri.toString()));
		});
	});
	
	describe('static checkOriginHeader()', function () {
		
		let spy = null;
		
		afterEach(function () {
			if (spy) spy.restore();
			spy = null;
		});
		
		it('passes if Origin header is present and valid', async function () {
			let checkOriginHeader = Router.checkOriginHeader();
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString()).set('Origin', 'http://cargohub.io');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes if Referer header is present and valid', async function () {
			let checkOriginHeader = Router.checkOriginHeader();
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString()).set('Referer', 'http://cargohub.io');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes if Referer header is a hostname instead of URI', async function () {
			let checkOriginHeader = Router.checkOriginHeader();
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString()).set('Referer', 'cargohub.io');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes if Origin header is a hostname instead of URI', async function () {
			let checkOriginHeader = Router.checkOriginHeader();
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString()).set('Origin', 'cargohub.io');
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('passes if Origin header is optional and missing', async function () {
			let checkOriginHeader = Router.checkOriginHeader({optional: true});
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			try {
				await superagent.get(app.uri.toString());
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
		});
		
		it('responds with status 400 and ERR_HEADER_ORIGIN_MISSING if non-optional value misses', async function () {
			let checkOriginHeader = Router.checkOriginHeader();
			app.get('/', checkOriginHeader);
			app.get('/', function (req, res, next) {
				if (!res.headersSent) res.status(200).send({});
				next();
			});
			app.use(Server.createHttpErrorHandler());
			app.use('/', suppressErrorLog);
			await expectErrorResponse(400, 'ERR_HEADER_ORIGIN_MISSING',
				superagent.get(app.uri.toString()));
		});
	});
	
	describe('static createGenericListRouter()', function () {
		
		it('passes the list query parameters to the router function', async function () {
			let Promise = bluebird;
			let serverPromise = new Promise(function (resolve, reject) {
				app.get('/', Router.createGenericListRouter(function (listOptions, req, res) {
					resolve(listOptions);
					return [1, 2, 3, 4];
				}));
				app.use(Server.createHttpErrorHandler());
				app.use('/', suppressErrorLog);
			});
			let resp = null;
			try {
				resp = await superagent.get(app.uri.toString() + "?pos=0&limit=10&orderBy=id,asc&orderBy=description");
			} catch (err) {
				if (err.response) assert.fail(true, true, util.format('Request failed: %d %s', err.response.status, err.response.get('X-Error')));
				throw err;
			}
			
			let listOptions = await serverPromise;
			assert.deepEqual(listOptions, {
				offset: 0, limit: 10, orderBy: ['id,asc', 'description']
			});
			assert.deepEqual(resp.body, [1, 2, 3, 4]);
			assert.equal(resp.get('X-List-Offset'), 0);
			assert.equal(resp.get('X-List-Count'), 4);
			assert.equal(resp.get('X-List-Limit'), 10);
			assert.equal(resp.get('X-List-Order'), 'id;asc,description');
		});
		
	});
	
});

