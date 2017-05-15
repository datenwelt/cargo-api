const Promise = require('bluebird');

const RSA = require('../../src/rsa');
const fs = Promise.promisifyAll(require('fs'));

const jwt = Promise.promisifyAll(require('jsonwebtoken'));
const NodeRSA = require('node-rsa');

const chai = require('chai');
const it = require("mocha").it;
const describe = require("mocha").describe;
const expect = chai.expect;

describe("utils/rsa.js", function () {

	const unencryptedPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0ukwklDp1CUNOhZCraBZ8vT8EKVvXFNbJtkrX+tBF2zFckw8
l099Gx+lab8nklsvY8nh/odUMIOv8tvm+tDUDe7kMkkgKsgREnn0mQQj3uU9KzxL
BEYuFpWKP2sqMGv2Xp6vhPWDNgzUykN4Q0MgOc8BmFDuoIKepcnvaKU4l3rg6dW4
RMaEWb0EUTg2rX9ESmsNKu7io6I7esPoWS4tJtBUJq7IWQl5Wpj/P3qMS01QZbZz
hvzOSdUyp3CVHA8aDyAJ3H++e+wsOGUBlh7Tpxh1yxFIPBtZH7P7gs90V2AKXwn1
j9oZwZ7Ox7tBL7Eag/Wk4vEx2K3saSNI54GFSwIDAQABAoIBADiaBEMAHACnAOm5
16MpCXq+bHc7LqukYy4F0jInvIxA0Kxf8VLaLkT9NTMv7brFZe5t24ynXNy4Opv+
j/p32LD0j6E/JrbUgmBnAlGeXtIOy1+zCp7XBr9g2n0ykVv1XWT/STNxgAkdYG33
tWq3tQpOl6r87U1+QH1VuD5pOMrN3iln9cEwh1PPkML1py8QVW68dkzTfnuD7lm3
bcCWGiUNN17OsaiaIa/paVLXR3v8lB01slVvC+LmJymp2xE0Osdqt4kVzqaakNsN
f54rWuBwGgt+yXjVzdjlkWSEM0sQ8VZ1lHSbdCCsPAnbU/Iqv+fWAT8ZbbPLF9Pv
RmFgWmECgYEA/RiCc0dZxQr/7b4QhihkggxuX0jKGC0KgvAzpCqesHESFWNQVoss
LlAGzIbzUkvZhfxc9wwlP0htNYGkJNncMGnNmUvU0mEM9ZPaSx9pWZoN9FcEKyRs
w/Th1Dm5YzDEdqgdL7HdBOChti84vl+4UyiEcqqrwOI1GPXuS41LC+UCgYEA1VTC
MZXfq0ZBIFG8tJXDTYWDgVM989+H6mnCSU4eYZdNdsWcCT+h37WUrwUjk2DqCX9j
n5mfAZ2G0PXPKg6f9joOZN2PCbvWMm1fLrIrAsIRDG8XHRkW/jfBLXwfj1PXp94u
lDsHJKexg6J5k6zESn4dSICo7h8KcYkcgL+2GW8CgYABB/eIFrNT7S6Lvml80m9O
ZFSSyM4h+RUA4Y+kTJQm7d7//U6Xe6uraKIOdUJKhIqXVCbgzsjcECR5wlRz3fta
qyOuSzPLw5905KxQAAnC1rDV3QDkWBqlVbsRzUZnFAzI2vh7eEMJQQ0Hm/ukMumi
VRjtCqr2dzV2K5JT9nhmzQKBgDCGLgHPYGf5+/hY/z5oTltEwkvZXl8peiX01m+M
KFb0bndUrZBg+/YBvIcu+Q+d3L46TrPP4p4gcbj4IJ4lY3dDb2C8ELwbELa5sAvU
FPp0oCIe5rgEq/k5P2SUNi2I2aXiYN/wqUhKKJOTkmnnw2JaW1jRgxteziZTFLuo
X8hbAoGBAL2qMbG/kxTE3f8jdnn7z9MoZZism0JzlGXx0q81hXRruRiGDZ5hJyLv
tq0LbuT1N38IOpBDtqfMHlHHk9SRK/Mx0b6a0uATSb+1TYIZdgF3wdKmm9h4dVdy
Z2n/LW9xVrQQiP+xiEWTlzgPiQXt/uynBCwPTWYino5Rsu3He5P0
-----END RSA PRIVATE KEY-----`;

	describe("RSA.evpBytesToKey()", function () {

		it("generates the expected key and IV for AES-128-CBC", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const { key, iv } = RSA.PEMReader.evpBytesToKey(passphrase, {cipher: 'AES-128-CBC', salt: salt});
			expect(key.toString('hex')).to.equal('747783301f72d2ddbe5a19c8f1e08254');
			expect(iv.toString('hex')).to.equal('fa5277af059220de3ca0f9a2d2c30a1d');
		});

		it("generates the expected key and IV for AES-192-CBC", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const {key, iv} = RSA.PEMReader.evpBytesToKey(passphrase, {cipher: 'AES-192-CBC', salt: salt});
			expect(key.toString('hex')).to.equal('747783301f72d2ddbe5a19c8f1e08254fa5277af059220de');
			expect(iv.toString('hex')).to.equal('3ca0f9a2d2c30a1da0ed7665f278bdd6');
		});

		it("generates the expected key and IV for AES-256-CBC", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const {key, iv} = RSA.PEMReader.evpBytesToKey(passphrase, {cipher: 'AES-256-CBC', salt: salt});
			expect(key.toString('hex')).to.equal('747783301f72d2ddbe5a19c8f1e08254fa5277af059220de3ca0f9a2d2c30a1d');
			expect(iv.toString('hex')).to.equal('a0ed7665f278bdd69710ed632cb3917d');
		});

		it("generates the expected key and IV for DES-CBC", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const {key, iv} = RSA.PEMReader.evpBytesToKey(passphrase, {cipher: 'DES-CBC', salt: salt});
			expect(key.toString('hex')).to.equal('747783301f72d2dd');
			expect(iv.toString('hex')).to.equal('be5a19c8f1e08254');
		});

		it("generates the expected key and IV for DES-EDE3-CBC", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const {key, iv} = RSA.PEMReader.evpBytesToKey(passphrase, {cipher: 'DES-EDE3-CBC', salt: salt});
			expect(key.toString('hex')).to.equal('747783301f72d2ddbe5a19c8f1e08254fa5277af059220de');
			expect(iv.toString('hex')).to.equal('3ca0f9a2d2c30a1d');
		});

		it("generates the expected key and IV for arbitrary key and IV sizes with an alternative hash", function () {
			const salt = "13F689619F77E4E55F68556C1A9FEEF8";
			const passphrase = "test123456";
			const {key, iv} = RSA.PEMReader.evpBytesToKey(passphrase, {
				cipher: 'DES-EDE3-CBC',
				salt: salt,
				keyLength: 64,
				ivLength: 30,
				count: 10,
				hash: 'SHA1'
			});
			expect(key.toString('hex')).to.equal('9e6e11a8015ba3bc13f0c58bdd286fd9a9128269a6f623accbd2678eec6f5a6d95ab375ebeb002a36fa662ade4132494f9895c21c4a9b73527b00390de1cf405');
			expect(iv.toString('hex')).to.equal('43f447d993863c59cab29e3cf64d6d457b495feb2db635b8884286b61a40');
		});

	});

	describe("RSA.readPrivateKey()", function () {

		it("reads an unencrypted private key", async function () {
			const data = await fs.readFileAsync('test/data/rsa/privkey.pem');
			const privkey = RSA.readPrivateKey(data);
			expect(privkey).to.equal(unencryptedPrivateKey);
		});

		it("reads an encrypted private key", async function () {
			const data = await fs.readFileAsync('test/data/rsa/privkey.encrypted.pem');
			const privkey = RSA.readPrivateKey(data, 'test123456');
			expect(privkey).to.equal(unencryptedPrivateKey);
		});

		it("returns a private key usable by module 'jsonwebtokens'", async function () {
			const data = await fs.readFileAsync('test/data/rsa/privkey.encrypted.pem');
			const privkey = RSA.readPrivateKey(data, 'test123456');
			await jwt.sign({}, privkey, {
				expiresIn: "1d",
				subject: "cargo-auth",
				algorithm: "RS256"
			});

		});

		it("returns a private key usable by module 'node-rsa'", async function () {
			const data = await fs.readFileAsync('test/data/rsa/privkey.encrypted.pem');
			const privkey = RSA.readPrivateKey(data, 'test123456');
			const key = new NodeRSA();
			key.importKey(privkey, 'private');
		});

		it("returns a private key usable by module 'node-rsa' for verification of JWTs", async function () {
			const data = await fs.readFileAsync('test/data/rsa/privkey.encrypted.pem');
			const privkey = RSA.readPrivateKey(data, 'test123456');
			const key = new NodeRSA(privkey);
			const pubkey = key.exportKey('public');
			const token = await jwt.sign({
				pbm: {
					ver: "1b5de",
					val: "ffff"
				},
				usr: "job",
				org: "1",
				rnw: "100448484848"
			}, privkey, {
				expiresIn: "1d",
				subject: "cargo-auth",
				algorithm: "RS256"
			});
			const payload = await jwt.verify(token, pubkey, {algorithm: 'RS256'});
			expect(payload.sub).to.equal("cargo-auth");
		});


	});

});
