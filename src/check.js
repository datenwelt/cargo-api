const _ = require('underscore');
const VError = require('verror');

function chain(check, value) {
	let chained = {};
	chained = _.extend(chained, _.mapObject(check, function (fn) {
		return fn.bind(chained, value);
	}));
	chained.val = function () {
		return value;
	};
	return chained;
}

function error(...args) {
	return new VError({
		name: "CargoCheckError",
		
	}, ...args);
}

const Check = {
	
	not: function () {
		return _.mapObject(this, function (fn) {
			// eslint-disable-next-line no-invalid-this
			return function (...args) {
				let msg = args.length === fn.length ? args[args.length - 1] : "";
				try {
					fn(...args);
				} catch (err) {
					return this;
				}
				throw error(msg);
				// eslint-disable-next-line no-invalid-this
			}.bind(this);
		}, this);
	},
	
	isBlank: function (value, msg) {
		if (value === '' || _.isUndefined(value) || _.isNull(value)) return this;
		throw error(msg);
	},
	
	equals: function (value1, value2, msg) {
		// eslint-disable-next-line eqeqeq
		if (value1 == value2) {
			return this;
		}
		throw error(msg);
	},
	
	string: function (value, msg) {
		if (_.isString(value)) return this;
		if (_.isUndefined(value) || _.isNull(value)) return chain(Check, "");
		if (_.isNumber(value) || _.isBoolean(value)) return chain(Check, String(value));
		throw error(msg);
	},
	
	trim: function (value, msg) {
		value = this.string(msg).val().trim();
		return chain(Check, value);
	},
	
	minLength: function (value, length, msg) {
		value = this.string(msg).val();
		if (value.length < length) throw error(msg);
		return chain(Check, value);
	},
	
	maxLength: function (value, length, msg) {
		value = this.string(msg).val();
		if (value.length > length) throw error(msg);
		return chain(Check, value);
	},
	
	matches: function (value, regex, msg) {
		value = this.string(msg).val();
		if (!value.match(regex)) throw error(msg);
		return chain(Check, value);
	},
	
	transform: function (value, transformer, msg) {
		try {
			value = transformer(value);
		} catch (err) {
			throw error(msg);
		}
		return chain(Check, value);
	}
	
	
};

module.exports = chain.bind(null, Check);
