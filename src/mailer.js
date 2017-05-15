const bluebird = require('bluebird');
const changecase = require('change-case');
const mailparser = require('mailparser');
const fs = bluebird.promisifyAll(require('fs'));
const Handlebars = require('handlebars');
const nodemailer = require('nodemailer');
const path = require('path');
const VError = require('verror');

class Mailer {

	constructor() {
		this.transporter = null;
		this.templates = {};
	}

	async init(config, state) {
		const smtpConfig = config.smtp;
		if (!smtpConfig) {
			throw new VError('Missing "[smtp]" section in configuration');
		}
		smtpConfig.port = smtpConfig.port || (smtpConfig.secure ? 465 : 25);
		try {
			this.transporter = nodemailer.createTransport(smtpConfig);
		} catch (err) {
			throw new VError(err, "Unable to initialize SMTP");
		}
		if (!config.templates || !config.templates.directory) {
			throw new VError('Missing "[templates]" section in configuration');
		}

		const templateDir = config.templates.directory;
		const files = await fs.readdirAsync(templateDir, 'utf8');
		for (let file of files) {
			file = path.join(templateDir, file);
			let ext = path.extname(file);
			if ( ext !== '.eml' ) continue;
			let templateName = path.basename(file);
			templateName = templateName.substr(0, templateName.length - ext.length);
			// eslint-disable-next-line no-await-in-loop
			let stats = await fs.statAsync(file);
			if (!stats.isFile()) continue;
			// eslint-disable-next-line no-await-in-loop
			let data = await fs.readFileAsync(file, 'utf8');
			let template = Handlebars.compile(data);
			this.templates[templateName] = template;
		}
		for ( let key of Object.keys(this.templates) ) {
			this.mixinTemplate(key, this.templates[key]);
		}

		state = state || {};
		state.mailer = this;
		return this;
	}

	mixinTemplate(name, template) {
		let fnName = changecase.camel("send." + name);
		if ( this[fnName] ) throw new VError('Unable to setup method "%s" for template "%s", property already exists', fnName, name);
		const sendFn = async function(input) {
			function flatten(addressObject) {
				let addr = [];
				for ( let val of addressObject.value ) {
					addr.push(val.address);
				}
				return addr.join(',');
			}
			const raw = template(input);
			const parsed = await mailparser.simpleParser(raw);
			const message = {};
			message.envelope = {
				from: flatten(parsed.from),
				to: flatten(parsed.to),
			};
			if ( parsed.cc ) message.envelope.cc = flatten(parsed.cc);
			if ( parsed.bcc ) message.envelope.bcc = flatten(parsed.bcc);
			message.raw = raw;
			await this.transporter.sendMail(message);
		}.bind(this);
		this[fnName] = sendFn;
	}

}

module.exports = Mailer;
