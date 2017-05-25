/* eslint-disable class-methods-use-this */

const bluebird = require('bluebird');
const changecase = require('change-case');
const EventEmitter = require('eventemitter2').EventEmitter2;
const JWT = bluebird.promisifyAll(require('jsonwebtoken'));
const moment = require('moment');
const VError = require('verror');

const Checks = require('./checks');

class Router extends EventEmitter {
	
	constructor(name) {
		super();
		this.name = name;
	}
	
	init(config, state) {
		state = state || {};
		state.routers = state.routers || [];
		state.routers.push(this);
	}
	
	shutdown() {
		this.removeAllListeners();
	}
	
	static asyncRouter(router) {
		return function (req, res, next) {
			const result = router(req, res, next);
			if (result.then && result.catch) {
				return result.catch(next);
			}
			return result;
		};
	}
	
	static requiresAuthentication() {
		return function (req, res, next) {
			if (res.headersSent) return next();
			if (req.username) return next();
			if (!res.get('WWW-Authenticate')) res.set('WWW-Authenticate', "* realm='Authorizazion required.'");
			res.append('X-Error', 'ERR_UNAUTHENTICATED_ACCESS');
			throw new VError(res.get('X-Error'));
		};
	}
	
	static checkSessionToken(rsaPublicKey) {
		return Router.asyncRouter(async function (req, res, next) {
			if (res.headersSent) return next();
			if (req.username) return next();
			const authHeader = req.get('Authorization');
			if (!authHeader) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			let [authType, authToken] = authHeader.split(/\s+/);
			if (!authType || authType.toLowerCase() !== 'bearer') {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			authToken = (authToken || "").trim();
			if (!authToken) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				return next();
			}
			let payload = null;
			try {
				payload = await JWT.verifyAsync(authToken, rsaPublicKey);
			} catch (err) {
				if (err.name === 'JsonWebTokenError') {
					res.status(403).append('X-Error', 'ERR_INVALID_AUTHORIZATION_TOKEN');
					return next();
				}
				if (err.name === 'TokenExpiredError') {
					res.status(410).append('X-Error', 'ERR_EXPIRED_AUTHORIZATION_TOKEN');
					return next();
				}
				throw new VError(err, 'Error validating token');
			}
			req.sessionId = payload.sess;
			if (payload.usr) {
				if (payload.usr.id) req.userId = payload.usr.id;
				if (payload.usr.nam) req.username = payload.usr.nam;
			}
			req.token = payload;
			res.append('Vary', 'Authorization');
			res.status(200);
			return next();
		});
	}
	
	static checkBodyField(fieldName, options) {
		options = Object.assign({
			optional: false,
			cast: null,
			type: 'string',
			minLength: null,
			maxLength: null,
			match: null,
			notBlank: null,
			check: null,
			transform: null
		}, options);
		const errorPrefix = "ERR_BODY_" + changecase.constantCase(fieldName) + "_";
		return function (req, res, next) {
			// eslint-disable-next-line no-undefined
			if (!req.body) res.set('X-Error', 'ERR_BODY_MISSING').sendStatus(400);
			else {
				try {
					let value = req.body[fieldName];
					let isPresent = Checks.optional(options.optional, value);
					if (isPresent) {
						if (options.cast) value = Checks.cast(options.cast, value);
						if (options.type) value = Checks.type(options.type, value);
						if (options.transform) value = Checks.transform(options.transform, value);
						if (options.check) value = Checks.check(options.check, value);
						if (options.notBlank) value = Checks.notBlank(value);
						if (options.minLength) value = Checks.minLength(options.minLength, value);
						if (options.maxLength) value = Checks.maxLength(options.maxLength, value);
						if (options.match) value = Checks.match(options.match, value);
						req.body[fieldName] = value;
					}
				} catch (err) {
					if (err instanceof VError && err.name === 'CargoCheckError') {
						res.set('X-Error', errorPrefix + err.message).status(400);
						return next(err);
					}
					throw new VError(err, 'Internal error in request body check');
				}
			}
			return next();
		};
	}
	
	static serialize(data) {
		if (data instanceof Date) {
			return moment(data).toISOString();
		}
		if (data && data.toISOString) {
			return data.toISOString();
		}
		if (typeof data === 'function') {
			// eslint-disable-next-line no-undefined
			return undefined;
		}
		// eslint-disable-next-line no-undefined
		if (data === undefined || data === null || typeof data === 'string' || typeof data === 'number' || typeof data === 'boolean') {
			return data;
		}
		if (Array.isArray(data)) {
			let result = [];
			for (let idx = 0; idx < data.length; idx++) {
				let value = data[idx];
				result[idx] = Router.serialize(value);
			}
			return result;
		}
		let keys = Object.keys(data);
		let result = {};
		for (let key of keys) {
			let value = data[key];
			// eslint-disable-next-line no-undefined
			if (value !== undefined) {
				key = changecase.camel(key);
				result[key] = Router.serialize(value);
			}
		}
		return result;
	}
	
}

module.exports = Router;
