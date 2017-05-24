const describe = require('mocha').describe;
const it = require("mocha").it;
const assert = require('chai').assert;
const sinon = require('sinon');

const check = require('../../src/check');

describe("check.js", function() {

	describe("not()", function() {

		it("inverts the following check", function() {
			assert.throws(check("").not().isBlank);
		});

		it("does not invert subsequent checks", function() {
			function fn () {
				check("X").not().isBlank("ERR_NOT_BLANK").equals("X", "ERR_NOT_EQUAL");
			}
			assert.doesNotThrow(fn);
		});

		it("throws the custom error of the following check", function() {
			function fn () {
				check("").not().isBlank("ERR_NOT_BLANK");
			}
			assert.throws(fn, "ERR_NOT_BLANK");
		});

	});

	describe("isBlank()", function() {

		it("passes if input is undefined.", function() {
			// eslint-disable-next-line no-undefined
			check(undefined).isBlank();
		});

		it("passes if input is null.", function() {
			// eslint-disable-next-line no-undefined
			check(null).isBlank();
		});

		it("passes if input is an empty string.", function() {
			// eslint-disable-next-line no-undefined
			check("").isBlank();
		});

		it("fails if input is 0.", function() {
			// eslint-disable-next-line no-undefined
			assert.throws(check(0).isBlank);
		});

		it("fails if input is false.", function() {
			// eslint-disable-next-line no-undefined
			assert.throws(check(false).isBlank);
		});

	});

	describe("string()", function() {

		it("leaves strings the same", function() {
			assert.strictEqual(check("TEST").string().val(), "TEST");
		});

		it("converts numbers to strings", function() {
			assert.strictEqual(check(0).string().val(), "0");
		});

		it("converts booleans to strings", function() {
			assert.strictEqual(check(false).string().val(), "false");
		});

		it("converts undefined to empty string", function() {
			// eslint-disable-next-line no-undefined
			assert.strictEqual(check(undefined).string().val(), "");
		});

		it("converts null to empty string", function() {
			// eslint-disable-next-line no-undefined
			assert.strictEqual(check(null).string().val(), "");
		});

		it("fails to convert objects", function() {
			// eslint-disable-next-line no-undefined
			assert.throws(check({}).string);
		});

		it("fails to convert arrays", function() {
			// eslint-disable-next-line no-undefined
			assert.throws(check([]).string);
		});

		it("fails to convert functions", function() {
			// eslint-disable-next-line no-undefined
			assert.throws(check(function() {}).string);
		});

	});

	describe("trim()", function() {

		it("removes leading and trailing spaces", function() {
			assert.strictEqual(check(" TEST ").trim().val(), "TEST");
		});

		it("does implicit string conversion", function() {
			let ck = check(0);
			sinon.spy(ck, "string");
			assert.strictEqual(ck.trim().val(), "0");
			assert.isTrue(ck.string.calledOnce);
			ck.string.restore();
		});

	});

});
