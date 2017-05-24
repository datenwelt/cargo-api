const describe = require('mocha').describe;
const before = require('mocha').before;
const after = require('mocha').after;
const it = require("mocha").it;
const assert = require('chai').assert;

const Mailer = require('../../src/mailer');
const TestConfig = require('../test-utils/test-config');
const TestSmtp = require('../test-utils/test-smtpout');


describe('mailer.js', function() {

	let smtp = null;
	let config = null;

	before(async function() {
		config = await TestConfig.get();
		smtp = await TestSmtp.get();

	});

	after(async function() {
		if ( smtp ) {
			await TestSmtp.close();
			smtp = null;
		}
	});

	describe('send[TemplateName]()', function() {

		it('formats and sends mails from templates', async function() {
			let mailer = new Mailer();
			await mailer.init(config);
			assert.property(mailer, 'sendRegistration');
			let promise = smtp.waitForMessage();
			await mailer.sendRegistration({ email: 'testman@test123456.de', token: '9cfa2d1a83ced85268c3a7358fe64ffe06572e3d' });
			let msg = await promise;
			assert.include(msg.header.to.address, 'testman@test123456.de');
			assert.include(msg[0], '9cfa2d1a83ced85268c3a7358fe64ffe06572e3d');
		});

	});


});
