/* eslint-disable class-methods-use-this,no-new-func */

const bluebird = require('bluebird');
const changecase = require('change-case');
const EventEmitter = require('eventemitter2').EventEmitter2;
const HttpError = require('standard-http-error');
const JWT = bluebird.promisifyAll(require('jsonwebtoken'));
const moment = require('moment');
const URI = require('urijs');
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
	
	static requireSessionToken(rsaPublicKey) {
		return Router.asyncRouter(async function (req, res, next) {
			if (res.headersSent) return next();
			if (req.username) return next();
			const authHeader = req.get('Authorization');
			if (!authHeader) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"');
				throw new HttpError(401, 'ERR_UNAUTHENTICATED_ACCESS');
			}
			let [authType, authToken] = authHeader.split(/\s+/);
			if (!authType || authType.toLowerCase() !== 'bearer') {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				throw new HttpError(401, 'ERR_UNAUTHENTICATED_ACCESS');
			}
			authToken = (authToken || "").trim();
			if (!authToken) {
				res.append('WWW-Authenticate', 'Bearer realm="Retrieve a session token by login first"').status(401);
				throw new HttpError(401, 'ERR_UNAUTHENTICATED_ACCESS');
			}
			let payload = null;
			try {
				payload = await JWT.verifyAsync(authToken, rsaPublicKey);
			} catch (err) {
				if (err.name === 'JsonWebTokenError') {
					throw new HttpError(403, 'ERR_INVALID_AUTHORIZATION_TOKEN');
				}
				if (err.name === 'TokenExpiredError') {
					throw new HttpError(410, 'ERR_EXPIRED_AUTHORIZATION_TOKEN');
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
	
	static checkBodyField(fieldName, predicate, options) {
		options = Object.assign({optional: false}, options);
		const errorPrefix = "ERR_BODY_" + changecase.constantCase(fieldName) + "_";
		return function (req, res, next) {
			// eslint-disable-next-line no-undefined
			if (!req.body) throw new HttpError(400, 'ERR_BODY_MISSING');
			else {
				try {
					let value = req.body[fieldName];
					if (Checks.optional(options.optional, value))
						req.body[fieldName] = predicate(value, req, res);
					// eslint-disable-next-line callback-return
					next();
				} catch (err) {
					if (err.name === 'CargoCheckError') throw new HttpError(400, errorPrefix + err.message);
					throw new VError(err, 'Internal error in request body check');
				}
			}
		};
	}
	
	static checkRequestParameter(paramName, predicate) {
		const errorPrefix = "ERR_PARAM_" + changecase.constantCase(paramName) + "_";
		return function (req, res, next) {
			// eslint-disable-next-line no-undefined
			try {
				req.params[paramName] = predicate(req.params[paramName], req, res);
				// eslint-disable-next-line callback-return
				next();
			} catch (err) {
				if (err.name === 'CargoCheckError') throw new HttpError(400, errorPrefix + err.message);
				throw new VError(err, 'Internal error in request parameter check');
			}
			
		};
	}
	
	static checkQueryParameter(queryName, predicate, options) {
		options = Object.assign({optional: false}, options);
		const errorPrefix = "ERR_QUERY_" + changecase.constantCase(queryName) + "_";
		return function (req, res, next) {
			// eslint-disable-next-line no-undefined
			try {
				let value = req.query[queryName];
				if (Checks.optional(options.optional, value))
					req.query[queryName] = predicate(value, req, res);
				// eslint-disable-next-line callback-return
				next();
			} catch (err) {
				if (err.name === 'CargoCheckError') throw new HttpError(400, errorPrefix + err.message);
				throw new VError(err, 'Internal error in request query check');
			}
			
		};
	}
	
	static checkRequestHeader(headerName, predicate, options) {
		options = Object.assign({optional: false}, options);
		const errorPrefix = "ERR_HEADER_" + changecase.constantCase(headerName) + "_";
		return function (req, res, next) {
			// eslint-disable-next-line no-undefined
			try {
				let value = req.get(headerName);
				if (Checks.optional(options.optional, value))
					req.headers[headerName] = predicate(value, req, res);
				// eslint-disable-next-line callback-return
				next();
			} catch (err) {
				if (err.name === 'CargoCheckError') throw new HttpError(400, errorPrefix + err.message);
				throw new VError(err, 'Internal error in request header check');
			}
			
		};
	}
	
	static checkOriginHeader(options) {
		options = Object.assign({optional: false}, options);
		return function (req, res, next) {
			let origin = req.get('Origin') || req.get('Referer');
			if (!origin) {
				if (options.optional) return next();
				throw new HttpError(400, 'ERR_HEADER_ORIGIN_MISSING');
			}
			if (origin.match(/^https?:\/\//)) {
				try {
					origin = new URI(origin).hostname();
				} catch (err) {
					throw new HttpError(440, 'ERR_HEADER_ORIGIN_NOURL');
				}
			}
			req.origin = origin;
			return next();
		};
	}
	
	static createGenericListRouter(listGenerator) {
		return Router.asyncRouter(async function (req, res, next) {
			Router.checkQueryParameter('pos', (value) => {
				value = Checks.cast('number', value);
				return Checks.min(0, value);
			}, {optional: true})(req, res, new Function());
			Router.checkQueryParameter('limit', (value) => {
				value = Checks.cast('number', value);
				return Checks.min(0, value);
			}, {optional: true})(req, res, new Function());
			Router.checkQueryParameter('order-by', (value) => {
				value = Checks.cast('string', value).trim();
				return value;
			}, {optional: true})(req, res, new Function());
			Router.checkQueryParameter('order-dir', (value) => {
				value = Checks.cast('string', value).trim().toLowerCase();
				if (value !== 'asc' && value !== 'desc') throw new HttpError(400, 'ERR_QUERY_ORDER_DIR_INVALID');
				return value;
			}, {optional: true})(req, res, new Function());
			let listOptions = {
				pos: 0,
				limit: 10,
				orderBy: null,
				orderDirection: 'asc'
			};
			// eslint-disable-next-line no-undefined
			if (req.query.pos !== undefined && req.query.pos !== null) listOptions.pos = req.query.pos;
			// eslint-disable-next-line no-undefined
			if (req.query.limit !== undefined && req.query.pos !== null) listOptions.limit = req.query.limit;
			if (req.query['order-by']) listOptions.orderBy = req.query['order-by'];
			if (req.query['order-dir']) listOptions.orderDirection = req.query['order-dir'];
			let list = await listGenerator(listOptions, req, res);
			list = list || [];
			res.status(200);
			res.set('X-List-Count', list.length);
			res.set('X-List-Pos', listOptions.pos);
			res.set('X-List-Page-Size', listOptions.limit);
			if (listOptions.orderBy)
				res.set('X-List-Order', listOptions.orderBy + ";" + listOptions.orderDirection);
			res.send(list);
			next();
		});
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
