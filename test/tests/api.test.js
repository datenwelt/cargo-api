const describe = require("mocha").describe;
const it = require("mocha").it;
const assert = require("chai").assert;
const EventEmitter = require('eventemitter2').EventEmitter2;
const VError = require("verror");

const API = require("../../src/api");

describe('api.js', function () {

	describe("static createError()", function () {

		it("returns the expected VError instance", function () {
			const err = API.createError("ERR_TEST_ERROR");
			assert.instanceOf(err, Error);
			assert.instanceOf(err, VError);
			assert.deepProperty(err, "code");
			assert.strictEqual(err.name, "CargoModelError");
			assert.strictEqual(err.code, "ERR_TEST_ERROR");
		});

	});

	describe("constructor", function () {

		it("returns the expected Model instance", function () {
			const model = new API("io.cargohub.test", "SOME_SCHEMA");
			assert.instanceOf(model, API);
			assert.instanceOf(model, EventEmitter);
			assert.strictEqual(model.name, "io.cargohub.test");
		});

	});

	describe("error()", function () {

		it("returns a VError instance with all expected properties", function () {
			const model = new API("io.cargohub.test", null);
			model.on('error', function() {});

			const err = model.error(new VError('ERR_TEST_ERROR'));
			assert.instanceOf(err, Error);
			assert.instanceOf(err, VError);
			assert.strictEqual(err.message, "CargoModelError: UNKNOWN_ERROR_CODE: ERR_TEST_ERROR");
			assert.strictEqual(err.name, "CargoModelError");
			assert.strictEqual(err.model, "io.cargohub.test");
		});

		it("emits a VError instance with all expected properties", function (done) {
			const model = new API("io.cargohub.test", null);
			model.on('error', function(err) {
				try {
					assert.instanceOf(err, Error);
					assert.instanceOf(err, VError);
					assert.strictEqual(err.message, "CargoModelError: UNKNOWN_ERROR_CODE: ERR_TEST_ERROR");
					assert.strictEqual(err.name, "CargoModelError");
					assert.strictEqual(err.model, "io.cargohub.test");
					done();
				} catch (error) {
					done(error);
				}
			});
			model.error(new VError('ERR_TEST_ERROR'));
		});

	});

});
