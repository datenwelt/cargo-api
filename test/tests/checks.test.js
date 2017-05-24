/* eslint-disable no-unused-vars,no-undefined,max-lines */
const mocha = require('mocha');
const assert = require('chai').assert;

const describe = mocha.describe;
const it = mocha.it;
const after = mocha.after;
const afterEach = mocha.afterEach;
const before = mocha.before;
const beforeEach = mocha.beforeEach;

const moment = require('moment');

const Checks = require('../../src/checks');

describe('checks.js', function () {
	
	describe('optional()', function () {
		
		it('check passes when value is missing but optional', function () {
			Checks.optional(true, null);
			Checks.optional(true, undefined);
		});
		
		it('check passes when value is present and not optional', function () {
			Checks.optional(false, 'TEST');
			Checks.optional(false, 0);
		});
		
		it('check passes when value is present and optional', function () {
			Checks.optional(true, 'TEST');
			Checks.optional(true, 0);
		});
		
		it('check fails when value is missing and not optional', function () {
			assert.throws(function () {
				Checks.optional(false, null);
			}, 'MISSING');
			assert.throws(function () {
				Checks.optional(false, undefined);
			}, 'MISSING');
		});
		
	});
	
	describe('cast()', function () {
		
		it('casts to string in some cases', function () {
			assert.strictEqual(Checks.cast('string', null), '');
			assert.strictEqual(Checks.cast('string', undefined), '');
			assert.strictEqual(Checks.cast('string', 'TEST'), 'TEST');
			assert.strictEqual(Checks.cast('string', 0), '0');
			assert.strictEqual(Checks.cast('string', true), 'true');
			assert.strictEqual(Checks.cast('string', moment('2017-10-08T01:23:45Z').toDate()), '2017-10-08T01:23:45.000Z');
		});
		
		it('fails to cast to string in other cases', function () {
			assert.throws(function () {
				Checks.cast('string', {});
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('string', []);
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('string', function () {
				});
			}, 'INVALID');
		});
		
		it('casts to number in some cases', function () {
			assert.strictEqual(Checks.cast('number', null), 0);
			assert.strictEqual(Checks.cast('number', undefined), 0);
			assert.strictEqual(Checks.cast('number', 0), 0);
			assert.strictEqual(Checks.cast('number', true), 1);
			assert.strictEqual(Checks.cast('number', false), 0);
			assert.strictEqual(Checks.cast('number', '12345'), 12345);
			assert.strictEqual(Checks.cast('number', '12345.1'), 12345.1);
		});
		
		it('fails to cast to number in other cases', function () {
			assert.throws(function () {
				Checks.cast('number', {});
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('number', []);
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('number', function () {
				});
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('number', 'NaN');
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('number', 'TESTTEST');
			}, 'INVALID');
		});
		
		it('casts to boolean in some cases', function () {
			assert.strictEqual(Checks.cast('boolean', null), false);
			assert.strictEqual(Checks.cast('boolean', undefined), false);
			assert.strictEqual(Checks.cast('boolean', 0), false);
			assert.strictEqual(Checks.cast('boolean', 2), true);
			assert.strictEqual(Checks.cast('boolean', true), true);
			assert.strictEqual(Checks.cast('boolean', false), false);
			assert.strictEqual(Checks.cast('boolean', '12345'), true);
			assert.strictEqual(Checks.cast('boolean', '0'), true);
			assert.strictEqual(Checks.cast('boolean', ''), false);
		});
		
		it('fails to cast to boolean in other cases', function () {
			assert.throws(function () {
				Checks.cast('boolean', {});
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('boolean', []);
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('boolean', function () {
				});
			}, 'INVALID');
		});
		
		it('casts to date in some cases', function () {
			assert.instanceOf(Checks.cast('date', null), Date);
			assert.instanceOf(Checks.cast('date', undefined), Date);
			assert.equal(Checks.cast('date', 1495649067).toISOString(), moment.unix(1495649067).toISOString());
			assert.equal(Checks.cast('date', '2017-08-13T22:33:00.000Z').toISOString(), moment('2017-08-13T22:33:00.000Z').toDate().toISOString());
		});
		
		it('fails to cast to date in other cases', function () {
			assert.throws(function () {
				Checks.cast('date', {});
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('date', []);
			}, 'INVALID');
			assert.throws(function () {
				Checks.cast('date', function () {
				});
			}, 'INVALID');
		});
		
	});
	
	describe('type()', function () {
		
		it('passes when checking a string vs string', function () {
			assert.doesNotThrow(function () {
				Checks.type('string', 'TEST');
			});
		});
		
		it('throws when checking a string vs non-string', function () {
			assert.throws(function () {
				Checks.type('string', null);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', undefined);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', 0);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', true);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', false);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', {});
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', []);
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', new Date());
			}, 'NOSTRING');
			assert.throws(function () {
				Checks.type('string', function () {
				});
			}, 'NOSTRING');
		});
		
		it('passes when checking a number vs number', function () {
			assert.doesNotThrow(function () {
				Checks.type('number', 0);
			});
		});
		
		it('throws when checking a number vs non-number', function () {
			assert.throws(function () {
				Checks.type('number', null);
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', undefined);
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', 'TEST');
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', true);
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', false);
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', {});
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', []);
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', new Date());
			}, 'NONUMBER');
			assert.throws(function () {
				Checks.type('number', function () {
				});
			}, 'NONUMBER');
		});
		
		it('passes when checking a integer vs integer', function () {
			assert.doesNotThrow(function () {
				Checks.type('integer', 1);
			});
		});
		
		it('throws when checking a integer vs non-integer', function () {
			const expectedError = 'NOINTEGER';
			const targetType = 'integer';
			assert.throws(function () {
				Checks.type(targetType, null);
			}, expectedError);
			assert.throws(function () {
				Checks.type(targetType, undefined);
			}, expectedError);
			const values = ['TEST', true, false, {}, [], 123.5, new Date(), function () {
			}];
			for (let value of values) {
				assert.throws(function () {
					Checks.type(targetType, value);
				}, expectedError, "", "value " + value);
			}
		});
		
		it('passes when checking a boolean vs boolean', function () {
			assert.doesNotThrow(function () {
				Checks.type('boolean', false);
			});
			assert.doesNotThrow(function () {
				Checks.type('boolean', true);
			});
		});
		
		it('throws when checking a boolean vs non-boolean', function () {
			const expectedError = 'NOBOOLEAN';
			const targetType = 'boolean';
			assert.throws(function () {
				Checks.type(targetType, null);
			}, expectedError);
			assert.throws(function () {
				Checks.type(targetType, undefined);
			}, expectedError);
			const values = ['TEST', {}, [], 0, 0.0, new Date(), function () {
			}];
			for (let value of values) {
				assert.throws(function () {
					Checks.type(targetType, value);
				}, expectedError, "", "value " + value);
			}
		});
		
		it('passes when checking a array vs array', function () {
			assert.doesNotThrow(function () {
				Checks.type('array', [0, 1]);
			});
			assert.doesNotThrow(function () {
				Checks.type('array', []);
			});
		});
		
		it('throws when checking a array vs non-array', function () {
			const expectedError = 'NOARRAY';
			const targetType = 'array';
			assert.throws(function () {
				Checks.type(targetType, null);
			}, expectedError);
			assert.throws(function () {
				Checks.type(targetType, undefined);
			}, expectedError);
			const values = ['TEST', true, false, {}, 0, 1.2, new Date(), function () {
			}];
			for (let value of values) {
				assert.throws(function () {
					Checks.type(targetType, value);
				}, expectedError, "", "value " + value);
			}
		});
		
		it('passes when checking a object vs object', function () {
			assert.doesNotThrow(function () {
				Checks.type('object', {});
			});
			assert.doesNotThrow(function () {
				Checks.type('object', {'a': 1});
			});
		});
		
		it('throws when checking a object vs non-object', function () {
			const expectedError = 'NOOBJECT';
			const targetType = 'object';
			assert.throws(function () {
				Checks.type(targetType, null);
			}, expectedError);
			assert.throws(function () {
				Checks.type(targetType, undefined);
			}, expectedError);
			const values = ['TEST', true, false, [], 0, 1.2, new Date(), function () {
			}];
			for (let value of values) {
				assert.throws(function () {
					Checks.type(targetType, value);
				}, expectedError, "", "value " + value);
			}
		});
		
		it('passes when checking a date vs date', function () {
			assert.doesNotThrow(function () {
				Checks.type('date', new Date());
			});
		});
		
		it('throws when checking a date vs non-date', function () {
			const expectedError = 'NODATE';
			const targetType = 'date';
			assert.throws(function () {
				Checks.type(targetType, null);
			}, expectedError);
			assert.throws(function () {
				Checks.type(targetType, undefined);
			}, expectedError);
			const values = ['TEST', true, false, {}, [], 0, 1.2, function () {
			}];
			for (let value of values) {
				assert.throws(function () {
					Checks.type(targetType, value);
				}, expectedError, "", "value " + value);
			}
		});
		
	});
	
	describe('minLength()', function () {
		
		it('passes when checking a string above the minimum length', function () {
			assert.doesNotThrow(function () {
				Checks.minLength(10, "12345678901");
			});
		});
		
		it('passes when checking an array with the minimum length', function () {
			assert.doesNotThrow(function () {
				Checks.minLength(2, [1, 2]);
			});
		});
		
		it('fails when checking a string below the minimum length', function () {
			assert.throws(function () {
				Checks.minLength(10, "123456789");
			}, 'TOOSHORT');
		});
		
		it('fails when checking an array below the minimum length', function () {
			assert.throws(function () {
				Checks.minLength(2, [12]);
			}, 'TOOSHORT');
		});
		
		it('fails when checking against null', function () {
			assert.throws(function () {
				Checks.minLength(2, null);
			}, 'MISSING');
		});
		
		it('fails when checking against undefined', function () {
			assert.throws(function () {
				Checks.minLength(2, undefined);
			}, 'MISSING');
		});
		
		it('fails when checking against anything other than strings and arrays', function () {
			const values = [0, 0.0, new Date(), function () {
			}, true, false, {}];
			const expectedError = 'INVALID';
			for (let value of values) {
				assert.throws(function () {
					Checks.minLength(2, value);
				}, expectedError, "", "value " + value);
			}
		});
		
	});
	
	describe('maxLength()', function () {
		
		it('passes when checking a string with the minimum length', function () {
			assert.doesNotThrow(function () {
				Checks.maxLength(10, "1234567890");
			});
		});

		it('passes when checking a string below the minimum length', function () {
			assert.doesNotThrow(function () {
				Checks.maxLength(10, "123456780");
			});
		});
		
		it('passes when checking an array with the maximum length', function () {
			assert.doesNotThrow(function () {
				Checks.maxLength(2, [1, 2]);
			});
		});
		
		it('passes when checking an array below the maximum length', function () {
			assert.doesNotThrow(function () {
				Checks.maxLength(2, [1]);
			});
		});
		
		it('fails when checking a string above the maximum length', function () {
			assert.throws(function () {
				Checks.maxLength(10, "12345678901");
			}, 'TOOLONG');
		});
		
		it('fails when checking an array above the maximum length', function () {
			assert.throws(function () {
				Checks.maxLength(2, [12, 13, 14]);
			}, 'TOOLONG');
		});
		
		it('fails when checking against null', function () {
			assert.throws(function () {
				Checks.maxLength(2, null);
			}, 'MISSING');
		});
		
		it('fails when checking against undefined', function () {
			assert.throws(function () {
				Checks.maxLength(2, undefined);
			}, 'MISSING');
		});
		
		it('fails when checking against anything other than strings and arrays', function () {
			const values = [0, 0.0, new Date(), function () {
			}, true, false, {}];
			const expectedError = 'INVALID';
			for (let value of values) {
				assert.throws(function () {
					Checks.maxLength(2, value);
				}, expectedError, "", "value " + value);
			}
		});
		
	});
	
	describe('match()', function () {
		
		it('passes when checking a matching string aganist', function () {
			assert.doesNotThrow(function () {
				Checks.match(/^abcd$/, "abcd");
			});
		});
		
		it('fails when checking a not matching string', function () {
			assert.throws(function () {
				Checks.match(/^abcde$/, "abcd");
			}, "WRONGFORMAT");
		});
		
		it('fails when checking against null', function () {
			assert.throws(function () {
				Checks.match(/^abcde$/, null);
			}, 'MISSING');
		});
		
		it('fails when checking against undefined', function () {
			assert.throws(function () {
				Checks.match(/^abcde$/, undefined);
			}, 'MISSING');
		});
		
		it('fails when checking against anything other than strings', function () {
			const values = [0, 0.0, new Date(), function () {
			}, true, false, {}];
			const expectedError = 'INVALID';
			for (let value of values) {
				assert.throws(function () {
					Checks.match(/^abcdef$/, value);
				}, expectedError, "", "value " + value);
			}
		});
		
	});
	
	describe('notBlank()', function () {
		
		it('passes when checking a string with content', function () {
			assert.doesNotThrow(function () {
				Checks.notBlank("12223423");
			});
		});
		
		it('fails when checking a WS-only string', function () {
			assert.throws(function () {
				Checks.notBlank('    ');
			}, "EMPTY");
		});
		
		it('fails when checking an emoty string', function () {
			assert.throws(function () {
				Checks.notBlank('');
			}, "EMPTY");
		});
		
		it('fails when checking against anything other than strings', function () {
			const values = [0, 0.0, new Date(), function () {
			}, true, false, {}];
			const expectedError = 'INVALID';
			for (let value of values) {
				assert.throws(function () {
					Checks.notBlank(value);
				}, expectedError, "", "value " + value);
			}
		});
		
	});
});
