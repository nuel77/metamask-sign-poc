import {WagmiConfig, createClient, useSignMessage, mainnet} from 'wagmi'
import { getDefaultProvider } from 'ethers'
import { useAccount, useConnect, useDisconnect } from 'wagmi'
import { InjectedConnector } from 'wagmi/connectors/injected'
import Web3 from 'web3';
import {ApiPromise, Keyring, WsProvider} from '@polkadot/api';
import {
    blake2AsHex,
    cryptoWaitReady, secp256k1Compress,
    evmToAddress, encodeAddress, blake2AsU8a,
} from '@polkadot/util-crypto';
import {
    construct, createMetadata, getRegistry,
    methods,
} from '@substrate/txwrapper-polkadot';
import {EXTRINSIC_VERSION} from "@polkadot/types/extrinsic/v4/Extrinsic";
import {
    arrayify,
    computeAddress,
    hexlify,
    keccak256,
    recoverPublicKey,
    splitSignature,
    toUtf8Bytes
} from "ethers/lib/utils";
import {fromRpcSig, toCompactSig} from "ethereumjs-util";
import {hexToU8a, u8aToHex, u8aToU8a} from "@polkadot/util";
let elliptic = require('elliptic');
let ec = new elliptic.ec('secp256k1');

const client = createClient({
  autoConnect: true,
  provider: getDefaultProvider(),
})

export default function App() {
  return (
      <WagmiConfig client={client}>
        <Profile />
      </WagmiConfig>
  )
}

function Profile() {
    const { address, isConnected } = useAccount()
    const { connect } = useConnect({
        connector: new InjectedConnector(),
    })
    const { disconnect } = useDisconnect()
    const handleClick = async ()=>{
        if (window.ethereum) {
            try {
                const p="0xa40503008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e40b540255000000542400000f00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c37376af6d9cf5711c3a644470a092988aa35ad34900b1dc29bd1771e4c751656f"
                console.log("blake hash", blake2AsU8a(p,256))
                const privateKey= "0f5315135dffad49c9422d8368865c13c5dbdeed31405aad96214c6b71f11fcc"
                const keypair = ec.keyFromPrivate(privateKey)

                const web3= new Web3(Web3.givenProvider)
                let accounts = await web3.eth.getAccounts();
                let msg = "Some data"
                let prefix = "\x19Ethereum Signed Message:\n" + msg.length
                let msgHash = web3.utils.sha3(prefix+msg)
                //sign message with metamask
                let sig1 = await web3.eth.sign(msgHash, accounts[0]);
                console.log("initial signature", sig1)
                const sigObject= splitSignature(sig1)
                console.log("sig Object", sigObject)
                const pureSig = fromRpcSig(sig1);
                console.log("pure sig object", pureSig)
                console.log("signature", toCompactSig(pureSig.v, pureSig.r, pureSig.s))
                let publicKey = recoverPublicKey(arrayify(msgHash),sig1)
                console.log("signed by", arrayify(publicKey))
                const address=  computeAddress(publicKey)
                console.log("address: ",address)

                //sign message using normal ecdsa
                let normalSig = ec.sign(msgHash, keypair.getPrivate("hex"), "hex");
                console.log("normal sig", {r:normalSig.r.toString(), s: normalSig.s.toString()})

                //create a wrapper transaction
                await cryptoWaitReady();
                //polkadot.api.onfinality.io/public-ws
                let signedExtensions = {
                    ChargeTransactionPayment:{
                        extrinsic: {
                            signature_scheme:'u8',
                            asset_id: 'Option<u128>',
                            tip: 'Balance'
                        },
                        payload: {}
                    }
                }
                const userExtensions = {
                    ChargeTransactionPayment: {
                        extrinsic: {
                            signature_scheme: '1',
                            asset_id: '1',
                            tip:'1'
                        },
                        payload: {}
                    }
                }
                const provider= new WsProvider("ws://127.0.0.1:9944")
                const api = await ApiPromise.create({provider,signedExtensions})
                api.registry.setSignedExtensions([],userExtensions)
                const compressPubicKey= secp256k1Compress(arrayify(publicKey))
                console.log("compressed public key u8", arrayify(compressPubicKey))
                console.log({compressPubicKey})
                const accountId32 = blake2AsHex(compressPubicKey,256);
                console.log("hash", accountId32)
                const substrateAdder= encodeAddress(accountId32,88)
                console.log("substrate addr", substrateAdder);

                const apiTx = api.tx.ocex.registerMainAccount('esqAtwszqNAFdyCQRQmCLCgWNP4zWLXVY4h7siAaRTgD4JvRw')
                const keyring = new Keyring()
                const alice=keyring.addFromUri("//Alice")
                apiTx.signAndSend(alice,{} , ({ events = [], status }) => {
                    console.log('Transaction status:', status.type);

                    if (status.isInBlock) {
                        console.log('Included at block hash', status.asInBlock.toHex());
                        console.log('Events:');

                        events.forEach(({ event: { data, method, section }, phase }) => {
                            console.log('\t', phase.toString(), `: ${section}.${method}`, data.toString());
                        });
                    } else if (status.isFinalized) {
                        console.log('Finalized block hash', status.asFinalized.toHex());

                    }
                });
                return
                const {nonce} = (await api.query.system.account(substrateAdder)).toJSON()
                console.log("nonce", nonce)
                const signingPayload = api.createType('SignerPayload', {
                    method: apiTx,
                    nonce: nonce,
                    genesisHash: api.genesisHash,
                    blockHash: api.genesisHash,
                    runtimeVersion: api.runtimeVersion,
                    version: api.extrinsicVersion,
                    // signedExtensions:[{
                    //     ChargeTransactionPayment:{
                    //         extrinsic: {
                    //             signature_scheme:'1',
                    //             asset_id: '1',
                    //             tip: '1'
                    //         },
                    //         payload: {}
                    //     }
                    // }]
                });

                console.log("signed extensions", signingPayload.signedExtensions.toJSON())
                const extrinsicPayload = api.createType('ExtrinsicPayload', signingPayload.toPayload(), { version: api.extrinsicVersion })
                const u8a = extrinsicPayload.toU8a({ method: true })

                console.log("payload:", u8a);
                console.log("signing payload", signingPayload)
                const encoded = u8a.length > 256
                    ? blake2AsU8a(u8a)
                    : u8a;
                console.log("payloadHash", encoded.toString())
                console.log("something", u8aToU8a(encoded).toString())
                //TODO: wrap with v4 types
                let signatureEcdsa = await web3.eth.sign(u8aToHex(blake2AsU8a(encoded)), accounts[0]);
                console.log("signature ecdsa", signatureEcdsa)
                const signatureEcdsaU8= arrayify(signatureEcdsa)
                signatureEcdsaU8[signatureEcdsaU8.length-1]-=27;
                console.log("signature u8 mutated", signatureEcdsaU8)
                console.log("signature hex mutated", hexlify(signatureEcdsaU8))
                console.log("signature buffer", toUtf8Bytes(signatureEcdsa).length)


                //create multi-signature
                const multiSignature = api.createType("MultiSignature", {ecdsa: signatureEcdsaU8})
                console.log("multiSignature", multiSignature.toHex())
                apiTx.addSignature(substrateAdder, multiSignature.toHex(), signingPayload.toPayload());
                await apiTx.send(({ status, events, dispatchError }) => {
                    // status would still be set, but in the case of error we can shortcut
                    // to just check it (so an error would indicate InBlock or Finalized)
                    if (dispatchError) {
                        if (dispatchError.isModule) {
                            // for module errors, we have the section indexed, lookup
                            const decoded = api.registry.findMetaError(dispatchError.asModule);
                            const { docs, name, section } = decoded;

                            const errMsg = `${section}.${name}: ${docs.join(" ")}`;
                            console.log("error: ", errMsg)
                        } else {
                            // Other, CannotLookup, BadOrigin, no extra info
                            const errMsg = dispatchError.toString();
                            console.log("error: ", errMsg)
                        }
                    } else if (status.isInBlock) {
                        handleExtrinsicErrors(events, api);
                        const eventMessages = events.map(({ phase, event: { data, method, section } }) => {
                            return `event:${phase} ${section} ${method}:: ${data}`;
                        });
                        console.log({ isSuccess: true, eventMessages, hash: apiTx.hash.toHex() });
                    } else if (status.isFinalized) {
                        handleExtrinsicErrors(events, api);
                        const eventMessages = events.map(({ phase, event: { data, method, section } }) => {
                            return `event:${phase} ${section} ${method}:: ${data}`;
                        });
                        console.log({ isSuccess: true, eventMessages, hash: apiTx.hash.toHex() });
                    }
                })
            } catch (error) {
                console.log({ error })
            }
        }
    }
    if (isConnected)
        return (
            <>
            <div>
                Connected to {address}
                <button onClick={() => disconnect()}>Disconnect</button>
            </div>
            <div>
                Send transfer
                <button onClick={handleClick}>Send transfer</button>
            </div>
            </>
        )
    return <button onClick={() => connect()}>Connect Wallet</button>
}
export const handleExtrinsicErrors = (events, api) => {
    events
        // find/filter for failed events
        .filter(({ event }) => api.events.system.ExtrinsicFailed.is(event))
        // we know that data for system.ExtrinsicFailed is
        // (DispatchError, DispatchInfo)
        .forEach(
            ({
                 event: {
                     data: [error],
                 },
             }) => {
                if (error.isModule) {
                    // for module errors, we have the section indexed, lookup
                    const decoded = api.registry.findMetaError(error.asModule);
                    const { docs, method, section } = decoded;
                } else {
                    // Other, CannotLookup, BadOrigin, no extra info
                    console.log("log: ", error.toString());
                }
            }
        );
};