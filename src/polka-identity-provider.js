'use strict'

const IdentityProvider = require('./identity-provider-interface');
const { cryptoWaitReady, mnemonicGenerate, decodeAddress, schnorrkelVerify, encodeAddress } = require('@polkadot/util-crypto');
const { Keyring } = require('@polkadot/keyring');
const { u8aToHex, hexToU8a } = require('@polkadot/util');
const createPair = require('@polkadot/keyring/pair').default;

const SCHNORRKELL_TYPE = 'sr25519';
const type = 'polka-sr25519'



const restoreAccount = (json, password) => {
    const type = Array.isArray(json.encoding.content) ? json.encoding.content[1] : 'ed25519';
    const pair = createPair(
        { toSS58: encodeAddress, type },
        {
            // FIXME Just for the transition period (ignoreChecksum)
            publicKey: decodeAddress(json.address)
        },
        json.meta,
        hexToU8a(json.encoded)
    );


    try {
        pair.decodePkcs8(password);

    } catch (error) {
        console.log(error);
    }
    return pair;
}

class PolkaIdentityProvider extends IdentityProvider {
    constructor(options = {}) {
        super()
        this.wallet = options.wallet
    }

    // Returns the type of the identity provider
    static get type() { return type }

    // Returns the signer's id
    async getId(options = {}) {
        if (!this.wallet) {
            this.wallet = await this._createWallet(options)
        }
        return this.wallet.address
    }

    // Returns a signature of pubkeysignature
    async signIdentity(data, options = {}) {

        return this.wallet.signMessage(data)
    }

    static async verifyIdentity(identity) {

        var verifyStatus = false;
        await cryptoWaitReady();
        try {
            verifyStatus = schnorrkelVerify(identity.publicKey + identity.signatures.id, identity.signatures.publicKey, decodeAddress(identity.id));

        } catch (error) {
            console.log(error);
        }

        return verifyStatus;
    }

    async _createWallet(options = {}) {

        var newWallet;
        await cryptoWaitReady();
        const keyring = new Keyring({ type: SCHNORRKELL_TYPE });

        if (options.mnemonicOpts) {
            if (!options.mnemonicOpts.mnemonic) {
                throw new Error(`mnemonic is required`)
            }
            newWallet = keyring.addFromUri(options.mnemonicOpts.mnemonic, options.mnemonicOpts.path, SCHNORRKELL_TYPE);
        } else if (options.JsonOpts) {
            if (!options.JsonOpts.json) {
                throw new Error(`Encrypted json is required`)
            }
            if (!options.JsonOpts.password) {
                throw new Error(`Password is required`)
            }
            newWallet = restoreAccount(options.JsonOpts.json, options.JsonOpts.password)
        }
        else {
            let privatekey = mnemonicGenerate(12);
            newWallet = keyring.addFromUri(privatekey, {}, SCHNORRKELL_TYPE);
        }

        if (newWallet != null) {
            newWallet.signMessage = (data) => u8aToHex(newWallet.sign(data));
        }

        return newWallet;
    }
}

module.exports = PolkaIdentityProvider