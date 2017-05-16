/* eslint-disable new-cap */
const changecase = require('change-case');
const Moment = require('moment');
const EventEmitter2 = require('eventemitter2').EventEmitter2;
const VError = require('verror');

class API extends EventEmitter2 {
	
	constructor(name) {
		super({wildcard: true, delimiter: '.', newListener: false});
		this.name = name;
		this.logger = {
			error: function () {
			},
			info: function () {
			},
			warn: function () {
			},
			debug: function () {
			},
			trace: function () {
			}
		};
	}
	
	// eslint-disable-next-line class-methods-use-this
	init(config, state) {
		if (state) {
			state.apis = state.apis || {};
			state.apis[this.name] = state.apis[this.name] || this;
		}
		return this;
	}
	
	// eslint-disable-next-line require-await
	async close() {
		// Interface method
		this.removeAllListeners();
	}
	
	error(err, cause) {
		if (err instanceof VError && err.name === "CargoModelError") {
			err.cause = cause;
			err.model = this.name;
		} else if (err instanceof Error) {
			err = API.createError("UNKNOWN_ERROR_CODE", err, this.name);
		} else {
			err = API.createError(err, new Error(err), this.name);
		}
		this.emit('error', err);
		return err;
	}
	
	static createError(code, cause, model) {
		const error = new VError({
			name: "CargoModelError",
			cause: cause
		}, "CargoModelError: %s", code);
		error.code = code;
		error.model = model;
		return error;
	}
	
	static serialize(data) {
		if (data instanceof Date) {
			return Moment(data).toISOString();
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
				result[idx] = API.serialize(value);
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
				result[key] = API.serialize(value);
			}
		}
		return result;
	}
	
}

module.exports = API;
