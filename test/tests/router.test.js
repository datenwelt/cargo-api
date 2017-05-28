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

const Checks = require('../../src/checks');
const Router = require('../../src/router');
const Server = require('../../src/server');

let config = null;
let app = null;
let rsa = null;

function suppressErrorLog(err, req, res, next) {
	if (!res.headersSent) res.end();
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
			let checkBodyField = Router.checkBodyField('testField', (value) => { return value }, {optional: true});
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
			let checkBodyField = Router.checkBodyField('testField', (value) => {
				return Checks.cast('number', value);
			});
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
	
});

