'use strict'

const assert = require('assert')
const path = require('path')
const rmrf = require('rimraf')
const Keystore = require('orbit-db-keystore')
const Identities = require('../src/identities')
const PolkaIdentityProvider = require('../src/polka-identity-provider')
const Identity = require('../src/identity')
const keypath = path.resolve('./test/keys')
let keystore

const type = PolkaIdentityProvider.type
describe('Polka Identity Provider', function () {
    before(async () => {
        rmrf.sync(keypath)
        Identities.addIdentityProvider(PolkaIdentityProvider)
        keystore = new Keystore(keypath)
    })

    after(async () => {
        await keystore.close()
        rmrf.sync(keypath)
    })

    describe('create an polka identity', () => {
        let identity
        let wallet

        before(async () => {

            const options = { id: 'local-id', type, mnemonicOpts: {} };
            options.mnemonicOpts.mnemonic = 'swim usage treat horse inhale session radar balance minute rare surge gasp';
            const polkaIdentityProvider = new PolkaIdentityProvider()
            wallet = await polkaIdentityProvider._createWallet();
            identity = await Identities.createIdentity({ type, keystore, wallet });
        })

        it('polka id has the correct id', async () => {
            assert.strictEqual(identity.id, wallet.address)
        })

        it('created a key for id in keystore', async () => {
            const key = await keystore.getKey(wallet.address)
            assert.notStrictEqual(key, undefined)
        })

        it('polka id has the correct public key', async () => {
            const signingKey = await keystore.getKey(wallet.address)
            assert.notStrictEqual(signingKey, undefined)
            assert.strictEqual(identity.publicKey, keystore.getPublic(signingKey))
        })

        it('has a signature for the id', async () => {
            const signingKey = await keystore.getKey(wallet.address)
            const idSignature = await keystore.sign(signingKey, wallet.address)
            const verifies = await Keystore.verify(idSignature, signingKey.public.marshal().toString('hex'), wallet.address)
            assert.strictEqual(verifies, true)
            assert.strictEqual(identity.signatures.id, idSignature)
        })
        /* 
                it('has a signature for the publicKey', async () => {
                    const signingKey = await keystore.getKey(wallet.address);
                    const idSignature = await keystore.sign(signingKey, wallet.address);
                    console.log(signingKey, wallet.address, 'helo');
                    const publicKeyAndIdSignature = await wallet.signMessage(identity.publicKey + idSignature)
                    assert.strictEqual(identity.signatures.publicKey, publicKeyAndIdSignature)
                }); */
    })

    describe('verify identity', () => {
        let identity

        before(async () => {

            const options = { id: 'local-id', type, mnemonicOpts: {} };
            options.mnemonicOpts.mnemonic = 'swim usage treat horse inhale session radar balance minute rare surge gasp';
            identity = await Identities.createIdentity({ ...options, keystore, type })
        })

        it('polka identity verifies', async () => {
            const verified = await Identities.verifyIdentity(identity)
            assert.strictEqual(verified, true)
        })

        it('polka identity with incorrect id does not verify', async () => {
            const identity2 = new Identity('NotAnId', identity.publicKey, identity.signatures.id, identity.signatures.publicKey, identity.type, identity.provider)
            const verified = await Identities.verifyIdentity(identity2)
            assert.strictEqual(verified, false)
        });
    })

    /*   describe('sign data with an identity', () => {
          let identity
          const data = 'hello friend'
  
          before(async () => {
              identity = await Identities.createIdentity({ keystore, type })
          })
  
          it('sign data', async () => {
              const signingKey = await keystore.getKey(identity.id)
              const expectedSignature = await keystore.sign(signingKey, data)
              const signature = await identity.provider.sign(identity, data, keystore)
              assert.strictEqual(signature, expectedSignature)
          })
  
          it('throws an error if private key is not found from keystore', async () => {
              // Remove the key from the keystore (we're using a mock storage in these tests)
              const modifiedIdentity = new Identity('this id does not exist', identity.publicKey, '<sig>', identity.signatures, identity.type, identity.provider)
              let signature
              let err
              try {
                  signature = await identity.provider.sign(modifiedIdentity, data, keystore)
              } catch (e) {
                  err = e.toString()
              }
              assert.strictEqual(signature, undefined)
              assert.strictEqual(err, `Error: Private signing key not found from Keystore`)
          })
  
          describe('verify data signed by an identity', () => {
              const data = 'hello friend'
              let identity
              let signature
  
              before(async () => {
                  identity = await Identities.createIdentity({ type, keystore })
                  signature = await identity.provider.sign(identity, data, keystore)
              })
  
              it('verifies that the signature is valid', async () => {
                  const verified = await identity.provider.verify(signature, identity.publicKey, data)
                  assert.strictEqual(verified, true)
              })
  
              it('doesn\'t verify invalid signature', async () => {
                  const verified = await identity.provider.verify('invalid', identity.publicKey, data)
                  assert.strictEqual(verified, false)
              })
          })
      }) */
})
