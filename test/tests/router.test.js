/* eslint-disable no-invalid-this,consistent-return */
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

const Router = require('../../src/router');

let config = null;
let app = null;
let rsa = null;

describe.only('utils/router.js', function () {
	
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
	
	describe('Router.checkSessionToken()', function () {
		
		it('responds with 200 if session token is valid', async function () {
			let sessionToken = await createValidSession('testman', rsa.rsaPrivateKey);
			let checkSessionToken = Router.checkSessionToken(rsa.rsaPublicKey);
			let spy = sinon.spy(checkSessionToken);
			app.use('/', spy);
			app.use('/', Router.requiresAuthentication());
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
			assert.isTrue(spy.called, "Router.checkSessionToken() has been called");
		});
		
		it('responds with 410 if session token is expired', async function () {
			let sessionToken = await createExpiredSession('testman', rsa.rsaPrivateKey);
			let checkSessionToken = Router.checkSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(checkSessionToken);
			let requiresAuthentication = Router.requiresAuthentication();
			let spy2 = sinon.spy(requiresAuthentication);
			app.use('/', spy1);
			app.use('/', spy2);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', function (err, req, res, next) {
				res.end();
			});
			try {
				let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 410);
				assert.isTrue(spy1.called, "Router.checkSessionToken() has been called");
				assert.isTrue(spy2.called, "Router.requiresAuthentication() has been called");
			}
		});
		
		it('responds with 401 if session token is missing', async function () {
			let checkSessionToken = Router.checkSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(checkSessionToken);
			let requiresAuthentication = Router.requiresAuthentication();
			let spy2 = sinon.spy(requiresAuthentication);
			app.use('/', spy1);
			app.use('/', spy2);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', function (err, req, res, next) {
				res.end();
			});
			try {
				let resp = await superagent.get(app.uri.toString());
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 401);
				assert.isTrue(spy1.called, "Router.checkSessionToken() has been called");
				assert.isTrue(spy2.called, "Router.requiresAuthentication() has been called");
			}
		});
		
		it('responds with 403 if session token is invalid', async function () {
			let sessionToken = "YXXXXXXZ";
			let checkSessionToken = Router.checkSessionToken(rsa.rsaPublicKey);
			let spy1 = sinon.spy(checkSessionToken);
			let requiresAuthentication = Router.requiresAuthentication();
			let spy2 = sinon.spy(requiresAuthentication);
			app.use('/', spy1);
			app.use('/', spy2);
			app.get('/', function (req, res, next) {
				res.sendStatus(200);
				next();
			});
			app.use('/', function (err, req, res, next) {
				res.end();
			});
			try {
				let resp = await superagent.get(app.uri.toString()).set('Authorization', 'Bearer ' + sessionToken);
				this.fail('Request succeeded unexpectedly');
			} catch (err) {
				assert.isDefined(err.response);
				assert.equal(err.response.status, 403);
				assert.isTrue(spy1.called, "Router.checkSessionToken() has been called");
				assert.isTrue(spy2.called, "Router.requiresAuthentication() has been called");
			}
		});
		
	});
	
});

async function createValidSession(username, rsaPrivateKey) {
	// Create a session id.
	let hash = crypto.createHash('SHA1');
	hash.update(new Date().getTime().toString());
	hash.update(crypto.randomBytes(16));
	const sessionId = hash.digest('hex');
	const iat = moment();
	const exp = iat.add(48, 'h');
	const token = await JWT.signAsync({
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
