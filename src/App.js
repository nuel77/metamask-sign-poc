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
import { web3Accounts, web3Enable, web3FromAddress } from '@polkadot/extension-dapp';


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
import {hexToU8a, u8aConcat, u8aToHex, u8aToU8a} from "@polkadot/util";
import {H256} from "@polkadot/types/interfaces/runtime";
import {ISubmittableResult} from "@polkadot/types/types/extrinsic";
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
const ExtrinsicPayloadPolkadex={
    asset_id:"u128",
    blockHash:"BlockHash",
    era: "ExtrinsicEra",
    genesisHash: "BlockHash",
    method:"Bytes",
    nonce:"Index",
    signature_scheme: "u128",
    specVersion:"u32",
    tip:"Balance",
    transactionVersion:"u32",
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
                const allInjected = await web3Enable('my cool dapp');
                const allAccounts = await web3Accounts();
                const injector = await web3FromAddress(allAccounts[0].address);
                const p="0xa40503008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480700e40b540255000000542400000f00000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c37376af6d9cf5711c3a644470a092988aa35ad34900b1dc29bd1771e4c751656f"
                console.log("blake hash", blake2AsU8a(p,256))
                const privateKey= "0f5315135dffad49c9422d8368865c13c5dbdeed31405aad96214c6b71f11fcc"
                const keypair = ec.keyFromPrivate(privateKey)

                const web3= new Web3(Web3.givenProvider)
                let accounts = await web3.eth.getAccounts();
                let msg = "Polkadex-THEA"
                let prefix = "\x19Ethereum Signed Message:\n" + msg.length
                let msgHash = web3.utils.sha3(prefix+msg)
                //sign message with metamask
                let sig1 = await web3.eth.personal.sign(msg, accounts[0]);
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
                // let normalSig = ec.sign(msgHash, keypair.getPrivate("hex"), "hex");
                // console.log("normal sig", {r:normalSig.r.toString(), s: normalSig.s.toString()})

                //create a wrapper transaction
                await cryptoWaitReady();
                //polkadot.api.onfinality.io/public-ws
                let signedExtensions = {
                    AssetsTransactionPayment:{
                        extrinsic: {
                            asset_id: 'u128',
                            tip: 'Balance',
                            signature_scheme:'u8',

                        },
                        payload: {
                            scheme:'u8'
                        }
                    }
                }
                const provider= new WsProvider("ws://127.0.0.1:9944")
                //
                // // await injector.metadata.provide({userExtensions:signedExtensions})
                const api = await ApiPromise.create({provider,signedExtensions})
                console.log("here2")
                const compressPubicKey= secp256k1Compress(arrayify(publicKey))
                console.log("compressed public key u8", arrayify(compressPubicKey))
                console.log({compressPubicKey})
                const accountId32 = blake2AsHex(compressPubicKey,256);
                console.log("hash", accountId32)
                const substrateAdder= encodeAddress(accountId32,88)
                console.log("substrate addr", substrateAdder);

                const keyring = new Keyring()
                const alice=keyring.addFromUri("//Alice")

                const apiTx = api.tx.system.remark('esqAtwszqNAFdyCQRQmCLCgWNP4zWLXVY4h7siAaRTgD4JvRw')
                const {nonce} = (await api.query.system.account(substrateAdder)).toJSON()
                console.log("nonce", nonce)
                console.log("registry", api.registry)

                const signerHelper = async (signingPayload) => {
                    console.log("signingPayload", signingPayload)
                    const extrinsicPayload = api.registry.createType('ExtrinsicPayload', signingPayload, { version: signingPayload.version});
                    console.log("extrinsic version", extrinsicPayload.specVersion.toHuman())
                    console.log("extrinsic payload", api.registry.getSignedExtensionExtra());
                    let u8a = extrinsicPayload.toU8a({method:true});
                    let encoded = u8a.length > 256 ? api.registry.hash(u8a) : u8a;
                    console.log("payload:", u8a.length);
                    // let encoded = u8a.length > 256
                    //     ? blake2AsU8a(u8a)
                    //     : u8a;
                   // encoded = u8aConcat(encoded,new Uint8Array([1]) )
                    //add signature scheme
                    console.log("encoded= ", encoded)
                    //TODO: wrap with v4 types

                    const {dataStr:data, dataJson}= getPayloadV3(u8aToHex(encoded));
                    let signatureEcdsa = await signPayloadV3(web3, accounts[0],data );
                    console.log("signature ecdsa", signatureEcdsa)
                    const signatureEcdsaU8= arrayify(signatureEcdsa)
                    signatureEcdsaU8[signatureEcdsaU8.length-1]-=27;
                    console.log("signature u8 mutated", signatureEcdsaU8)
                    console.log("signature hex mutated", hexlify(signatureEcdsaU8))
                    console.log("signature buffer", toUtf8Bytes(signatureEcdsa).length)

                    //create multi-signature
                    const multiSignature = api.createType("MultiSignature", {ecdsa: signatureEcdsaU8})
                    return multiSignature.toU8a();
                }

                //api.registry.setSignedExtensions([],signedExtensions)
                // apiTx.addSignature(substrateAdder, multiSignature.toHex(), signingPayload.toPayload());
                const signer = new mySigner({address:alice.address, signer:signerHelper})
                apiTx.signAndSend(substrateAdder,
                    {
                        signer:signer,
                        asset_id:"0",
                        tip:"1",
                        signature_scheme:"1",
                        scheme:"1"
                    },
                    ({ events = [], status }) => {
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
const signPayloadV3 = (web3, account, data)=>{
    console.log("signPayload", data)
    return new Promise((resolve,reject)=>{
        web3.currentProvider.sendAsync(
            {
                method: "eth_signTypedData_v3",
                params: [account, data],
                from: account
            },
            function(err, result) {
                if (err) {
                    reject(err)
                }
                resolve(result.result)
                const signature = result.result.substring(2);
                const r = "0x" + signature.substring(0, 64);
                const s = "0x" + signature.substring(64, 128);
                const v = parseInt(signature.substring(128, 130), 16);
                // The signature is now comprised of r, s, and v.
                console.log({r,s,v})
            }
        );
    })
}
const getPayloadV3 = (txhash)=>{
    console.log("salt" + getSalt())
    const domain = [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId" , type: "uint256"},
        { name: "verifyingContract", type: "address"},
        { name: "salt", type: "bytes32"}
    ];
    const EthereumSignerPayload = [
        { name: "transaction", type: "string" },
    ];
    const domainData = {
        name: "Polkadex Transaction",
        version: "3",
        chainId : 1,
        verifyingContract : "0x0000000000000000000000000000000000000001",
        salt: getSalt()
    };
    let message = {
        transaction: txhash,
    }
    const data = {
        types: {
            EIP712Domain: domain,
            EthereumSignerPayload: EthereumSignerPayload,
        },
        domain: domainData,
        primaryType: "EthereumSignerPayload",
        message: message
    };
    return {dataStr:JSON.stringify(data), dataJson:data}
}

class mySigner  {
    signer
    address
    constructor({address, signer}) {
        this.signer=signer
        this.address=address
    }
    async signPayload(payload){
        const sig= await this.signer(payload);
        return {id: 1, signature: sig}
    }
    async signRaw(val){
        return {id: 1, signature: await this.signer(val)}
    }
    async update (id, status ) {
        console.log({id,status})
        return;
    };
}

const getSalt= ()=>{
    let s= new Uint8Array([74, 70, 19, 182, 2, 77, 52, 166, 170, 200, 37, 169, 110, 153, 241, 72, 11, 229, 252, 40, 244, 207, 231, 54, 251, 170, 208, 69, 127, 91, 161, 229])
    return u8aToHex(s);
}