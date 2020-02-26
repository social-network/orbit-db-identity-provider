'use strict'

const IdentityProvider = require('./identity-provider-interface');
const { cryptoWaitReady, mnemonicGenerate, decodeAddress, schnorrkelVerify } = require('@polkadot/util-crypto');
const { Keyring } = require('@polkadot/keyring');
const { u8aToHex } = require('@polkadot/util');

const SCHNORRKELL_TYPE = 'sr25519';
const type = 'polka-sr25519'



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
                throw new Error(`Unencrypted json is required`)
            }
            newWallet = keyring.addFromJson(options.JsonOpts.json)
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