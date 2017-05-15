/* eslint-disable complexity, max-lines */
const bluebird = require('bluebird');
const fs = bluebird.promisifyAll(require('fs'));
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const VError = require('verror');

const BEGIN_RSA_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----';
const END_RSA_PRIVATE_KEY = '-----END RSA PRIVATE KEY-----';

class Parser {

	constructor(input) {
		this.input = input;
		this.pos = 0;
		this.eof = false;
	}

	readline() {
		if (this.eof || this.pos > this.input.length) {
			this.eof = true;
			return null;
		}
		let lineEnd = this.input.indexOf('\n', this.pos);
		if (lineEnd === -1) {
			lineEnd = this.input.length - 1;
		}
		lineEnd++;
		let line = this.input.substring(this.pos, lineEnd);
		this.pos = lineEnd;
		line = line.trim();
		return line;
	}

	skipUntil(match) {
		const lineStart = this.pos;
		while (!this.eof) {
			const line = this.readline();
			if (typeof match === 'string' && !line.startsWith(match)) continue;
			if (!line.match(match)) continue;
			this.pos = lineStart;
			return line;
		}
		return null;
	}

}

class PEMReader {

	/**
	 * Key derivation algorithm from OpenSSL. Generates a key from a passphrase with the
	 * required byte length for use by a given cipher algorithm. Supported algorithms are:
	 *
	 * <ol>
	 *     <li>AES-128-CBC (default)
	 *     <li>AES-192-CBC
	 *     <li>AES-256-CBC
	 *     <li>DES-CBC
	 *     <li>DES-EDE3-CBC (TripleDES)
	 *  </ol>
	 *
	 *  The cipher algorithms determine default key lengths and sizes of the IV. Both parameters can be
	 *  customized in the <code>options</code> parameter. If both parameters are present in the <code>options</code>
	 *  parameter, the cipher algorithm is ignored.
	 *
	 * @param {(string|Buffer)} passphrase  The passphrase as a string or Buffer.
	 * @param {object} [options]
	 * @param {string} [options.cipher=AES-128-CBC] The cipher algorithm which determines key and IV sizes.
	 * @param {string} [options.hash=MD5] The hashing algorithm to use.
	 * @param {string|Buffer} [options.salt] The salt which is either empty or has least 8 bytes. If a string is specified,
	 *                                       it is interpreted as a hex string and converted to byte values.
	 * @param {Number} [options.count=1] The number of hash rounds to perform during key derivation.
	 * @param {Number} [options.keyLength] The desired key length in bytes. Overrides the default value from options.cipher.
	 * @param {Number} [options.ivLength] The desired iv length in bytes. Overrides the default value from options.cipher.
	 *
	 * @see https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3)
	 */
	static evpBytesToKey(passphrase, options) {
		options = Object.assign({
			cipher: 'AES-128-CBC',
			hash: 'MD5',
			count: 1,
			salt: Buffer.alloc(0),
		}, options || {});

		// Key lengths and IV sizes for known algorithms.
		const configs = {
			'AES-128-CBC': {
				keyLength: 16,
				ivLength: 16
			},
			'AES-192-CBC': {
				keyLength: 24,
				ivLength: 16
			},
			'AES-256-CBC': {
				keyLength: 32,
				ivLength: 16
			},
			'DES-CBC': {
				keyLength: 8,
				ivLength: 8
			},
			'DES-EDE3-CBC': {
				keyLength: 24,
				ivLength: 8
			},
			'SEED-CBC': {
				keyLength: 16,
				ivLength: 16
			}
		};

		// Convert passphrase to a byte buffer.
		if (typeof passphrase === 'string') {
			passphrase = passphrase.length ? Buffer.from(passphrase) : Buffer.alloc(0);
		}
		if (!Buffer.isBuffer(passphrase)) {
			throw new VError('Parameter "passphrase" must be a string or a buffer.');
		}

		// Hash rounds (i.e. the "count" parameter from the EVP_bytesToKey()).
		let hashRounds = options.count;
		if (hashRounds <= 0) {
			throw new VError('Parameter "options.count" must be 1 or greater.');
		}
		hashRounds = Math.floor(hashRounds);

		const cipherAlgo = options.cipher;
		const hashAlgo = options.hash;

		const config = configs[cipherAlgo.toUpperCase()];
		if (!config) {
			throw new VError('Unsupported cipher "%s". Supported: %j', cipherAlgo, configs.keys());
		}

		// Override key and IV length if defined in the options parameter.
		let keyLength = options.keyLength || config.keyLength;
		let ivLength = options.ivLength || config.ivLength;

		// Create an 8 byte buffer for salt if there was a salt option. If no salt is used,
		// create an empty buffer instead.
		let salt = options.salt;
		if (typeof salt === 'string') {
			salt = !salt.length ? Buffer.alloc(0) : Buffer.from(salt, 'hex');
		}
		if (!Buffer.isBuffer(salt)) {
			throw new VError('Parameter "options.salt" must be a hex string or a Buffer');
		}
		if (salt.length > 0 && salt.length < 8) {
			throw new VError('Parameter "options.salt" must be empty or represent at least 8 bytes: options.salt = %d bytes', salt.length);
		}
		if (salt.length > 8) {
			salt = salt.slice(0, 8);
		}

		// Find size of hash by digesting some crap.
		let hash = crypto.createHash(hashAlgo);
		hash.update('XXX');
		const hashLength = hash.digest().length;

		// How many bytes are needed and how many iterations are required to get there?
		const bytesNeeded = keyLength + ivLength;
		const iterations = Math.ceil(bytesNeeded / hashLength);

		// Generate the key and IV bytes.
		let keyAndIv = Buffer.alloc(bytesNeeded);
		let d_prev = Buffer.alloc(0);
		let iteration = 0;
		while (iteration < iterations) {
			// Quote:
			//   D_i = HASH^count(D_(i-1) || data || salt)
			let hash = crypto.createHash(hashAlgo);
			hash.update(d_prev);
			hash.update(passphrase);
			hash.update(salt);
			let d_curr = hash.digest();
			let hashRound = 1;
			while (hashRound++ < hashRounds) {
				hash = crypto.createHash(hashAlgo);
				hash.update(d_curr);
				d_curr = hash.digest();
			}
			// Quote:
			//   The key and IV is derived by concatenating D_1, D_2, etc until enough data is available for the
			//   key and IV.
			d_curr.copy(keyAndIv, iteration * hashLength);
			d_prev = d_curr;
			iteration++;
		}
		let key = keyAndIv.slice(0, keyLength);
		let iv = keyAndIv.slice(keyLength, keyLength + ivLength);
		return {key: key, iv: iv};
	}

	/**
	 * Reads a PEM-encoded RSA private key from a buffer or string. It searches for the begin marker
	 * "-----BEGIN RSA PRIVATE KEY----" and returns everything from there to the end marker. If the
	 * private key is encrypted, the decrypted version is returned.
	 *
	 * @param {(string|Buffer)} bufferOrString The string or Buffer containing the private key.
	 * @param {string} [passphrase] An optional passphrase for descrpytion.
	 */
	static readPrivateKey(bufferOrString, passphrase) {
		let input = bufferOrString;
		if (Buffer.isBuffer(bufferOrString)) {
			input = bufferOrString.toString('utf8');
		}
		const parser = new Parser(input);
		if (!parser.skipUntil(BEGIN_RSA_PRIVATE_KEY)) {
			throw new VError('The input does not contain a PEM encoded private key');
		}

		let privateKey = parser.readline();

		let line = parser.readline();
		if (!line) {
			throw new VError('The input ended unexpectedly after %s', BEGIN_RSA_PRIVATE_KEY);
		}
		let matches = line.match(/^Proc-Type:\s+(.+)/);
		if (matches) {
			// Encrypted private key. Passphrase is needed.
			if (!passphrase) {
				throw new VError('Missing passphrase to decrypt private key.');
			}

			// Read Proc-Type and DEK-Info headers to find algorithm and IV.
			const proctype = matches[1].trim().toUpperCase();
			if (proctype !== '4,ENCRYPTED') {
				throw new VError('Unknown Proc-Type value: %s', proctype);
			}
			let line = parser.skipUntil('DEK-Info:');
			if (!line) {
				throw new VError('Missing DEK-Info for Proc-Type "%s"', proctype);
			}
			matches = line.match(/^DEK-Info:\s+(.+)(?:,(.+))/);
			if (!matches) {
				throw new VError('Unparseable DEK-Info: %s', line);
			}
			if (matches.length !== 3) {
				throw new VError('Missing IV in DEK-Info: %s', line);
			}
			const algo = matches[1];
			const iv = Buffer.from(matches[2], 'hex');

			// Skip to end of header.
			while ((line = parser.readline()) !== null) {
				if (line === "") break;
			}
			if (line !== "") {
				throw new VError('Missing empty line after PEM header.');
			}

			let {key: keyBuffer} = PEMReader.evpBytesToKey(passphrase, {cipher: algo, salt: iv});
			let decipher = crypto.createDecipheriv(algo, keyBuffer, iv);

			let data = "";
			while ((line = parser.readline()) !== null) {
				if (line.startsWith(END_RSA_PRIVATE_KEY)) break;
				data += decipher.update(line, 'base64', 'base64');
			}
			data += decipher.final('base64');
			privateKey = BEGIN_RSA_PRIVATE_KEY + "\n";
			let pos = 0;
			while (pos < data.length) {
				privateKey += data.charAt(pos++);
				if (pos % 64 === 0)
					privateKey += "\n";
			}
			if (!privateKey.endsWith("\n"))
				privateKey += "\n";
			privateKey += END_RSA_PRIVATE_KEY;
		} else {
			// Unencrypted private key.
			privateKey += "\n" + line + "\n";
			while ((line = parser.readline()) !== null) {
				privateKey += line;
				if (line.startsWith(END_RSA_PRIVATE_KEY)) {
					break;
				}
				privateKey += "\n";
			}
			if (!line)
				throw new VError('Missing %s after %s ', END_RSA_PRIVATE_KEY, BEGIN_RSA_PRIVATE_KEY);
		}
		return privateKey;
	}

	static readPublicKey() {
		throw new Error("Not implemented yet.");
	}

}

class RSA {

	static async init(config) {
		let rsa = null;
		if (config.privateKey) {
			let data = await fs.readFileAsync(config.privateKey, 'utf8');
			let passphrase = config.passphrase;
			let privateKey = PEMReader.readPrivateKey(data, passphrase);
			rsa = new NodeRSA(privateKey);
			rsa.rsaPrivateKey = rsa.exportKey('private');
			rsa.rsaPublicKey = rsa.exportKey('public');
		}
		if (config.publicKey) {
			let data = await fs.readFileAsync(config.publicKey, 'utf8');
			let publicKey = PEMReader.readPublicKey(data);
			rsa = new NodeRSA(publicKey);
			rsa.rsaPrivateKey = null;
			rsa.rsaPublicKey = rsa.exportKey('public');
		}
		if ( !rsa )
			throw new VError('Configuration did not contain any key information.');
		return rsa;
	}

	static readPrivateKey(stringOrBuffer, passphrase) {
		return PEMReader.readPrivateKey(stringOrBuffer, passphrase);
	}

	static readPublicKey(stringOrBuffer) {
		return PEMReader.readPublicKey(stringOrBuffer);
	}

}

RSA.PEMReader = PEMReader;

module.exports = RSA;
