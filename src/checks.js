/* eslint-disable id-length,no-undefined,complexity */
const _ = require('underscore');
const moment = require('moment');
const VError = require('verror');

const errorName = 'CargoCheckError';

class Checks {
	
	static optional(isOptional, value) {
		if (isOptional) return Checks;
		if (value === null || value === undefined) throw new VError({name: errorName}, 'MISSING');
		if (_.isString(value) && value === '') throw new VError({name: errorName}, 'MISSING');
		return value;
	}
	
	static cast(targetType, value) {
		switch (targetType) {
			case 'string':
				if (value === null || value === undefined) value = '';
				else if (_.isNumber(value)) value = Number(value).toString();
				else if (_.isBoolean(value)) value = Boolean(value).toString();
				else if (_.isDate(value)) value = moment(value).toISOString();
				else if (!_.isString(value)) throw new VError({name: errorName}, 'INVALID');
				break;
			case 'number':
				if (value === null || value === undefined) value = 0;
				else if (_.isString(value)) value = Number(value);
				else if (_.isBoolean(value)) value = value ? 1 : 0;
				else if (!_.isNumber(value)) throw new VError({name: errorName}, 'INVALID');
				if (_.isNaN(value) || !_.isFinite(value)) throw new VError({name: errorName}, 'INVALID');
				break;
			case 'integer':
				value = Checks.cast('number', value);
				value = Math.floor(value);
				break;
			case 'boolean':
				if (value === null || value === undefined) value = false;
				else if (_.isNumber(value)) value = value !== 0;
				else if (_.isString(value)) value = value !== '';
				else if (!_.isBoolean(value)) throw new VError({name: errorName}, 'INVALID');
				break;
			case 'date':
				if (value === null || value === undefined) value = new Date();
				else if (_.isNumber(value)) {
					value = moment.unix(value);
					if (!value.isValid()) throw new VError({name: errorName}, 'INVALID');
					value = value.toDate();
				} else if (_.isString(value)) {
					value = moment(value);
					if (!value.isValid()) throw new VError({name: errorName}, 'INVALID');
					value = value.toDate();
				} else if (!_.isDate(value)) throw new VError({name: errorName}, 'INVALID');
				break;
			default:
				throw new VError('Unable to cast type: ' + targetType);
		}
		return value;
	}
	
	static type(typeName, value) {
		switch (typeName) {
			case 'string':
				if (!_.isString(value)) throw new VError({name: errorName}, 'NOSTRING');
				break;
			case 'number':
				if (!_.isNumber(value)) throw new VError({name: errorName}, 'NONUMBER');
				if (_.isNaN(value)) throw new VError({name: errorName}, 'NONUMBER');
				if (!_.isFinite(value)) throw new VError({name: errorName}, 'NONUMBER');
				break;
			case 'integer':
				if (!_.isNumber(value)) throw new VError({name: errorName}, 'NOINTEGER');
				if (_.isNaN(value)) throw new VError({name: errorName}, 'NOINTEGER');
				if (!_.isFinite(value)) throw new VError({name: errorName}, 'NOINTEGER');
				if (Math.floor(value) !== value) throw new VError({name: errorName}, 'NOINTEGER');
				break;
			case 'boolean':
				if (!_.isBoolean(value)) throw new VError({name: errorName}, 'NOBOOLEAN');
				break;
			case 'array':
				if (!_.isArray(value)) throw new VError({name: errorName}, 'NOARRAY');
				break;
			case 'object':
				if (_.isArray(value)) throw new VError({name: errorName}, 'NOOBJECT');
				if (_.isFunction(value)) throw new VError({name: errorName}, 'NOOBJECT');
				if (_.isDate(value)) throw new VError({name: errorName}, 'NOOBJECT');
				if (!_.isObject(value)) throw new VError({name: errorName}, 'NOOBJECT');
				break;
			case 'date':
				if (!_.isDate(value)) throw new VError({name: errorName}, 'NODATE');
				break;
			default:
				throw new VError('Unable to check unknown type: ' + typeName);
		}
		return value;
	}
	
	static minLength(length, value) {
		if (value === null || value === undefined) throw new VError({name: errorName}, 'MISSING');
		else if (_.isString(value) || _.isArray(value))
			if (value.length < length) throw new VError({name: errorName}, 'TOOSHORT');
			else return value;
		else throw new VError({name: errorName}, 'INVALID');
	}
	
	static maxLength(length, value) {
		if (value === null || value === undefined) throw new VError({name: errorName}, 'MISSING');
		else if (_.isString(value) || _.isArray(value))
			if (value.length > length) throw new VError({name: errorName}, 'TOOLONG');
			else return value;
		else throw new VError({name: errorName}, 'INVALID');
	}
	
	static match(regex, value) {
		if (value === null || value === undefined) throw new VError({name: errorName}, 'MISSING');
		else if (_.isString(value))
			if (!regex.test(value)) throw new VError({name: errorName}, 'WRONGFORMAT');
			else return value;
		else throw new VError({name: errorName}, 'INVALID');
	}
	
	static notBlank(value) {
		if (value === null || value === undefined) throw new VError({name: errorName}, 'MISSING');
		else if (_.isString(value))
			if (value.trim() === '') throw new VError({name: errorName}, 'EMPTY');
			else return value;
		else throw new VError({name: errorName}, 'INVALID');
	}
	
	static check(value, predicate) {
		return predicate(value);
	}
	
	static transform(value, transformer) {
		return transformer(value);
	}
	
}

module.exports = Checks;

