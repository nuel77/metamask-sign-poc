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
                const provider= new WsProvider("wss://mainnet.polkadex.trade")
                const api = await ApiPromise.create({provider})
                const compressPubicKey= secp256k1Compress(arrayify(publicKey))
                console.log("compressed public key u8", arrayify(compressPubicKey))
                console.log({compressPubicKey})
                const accountId32 = blake2AsHex(compressPubicKey,256);
                console.log("hash", accountId32)
                const substrateAdder= encodeAddress(accountId32,88)
                console.log("substrate addr", substrateAdder);

                const apiTx = api.tx.balances.transfer('5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY', 1234568)
                const {nonce} = (await api.query.system.account(substrateAdder)).toJSON()
                const signingPayload = api.createType('SignerPayload', {
                    method: apiTx,
                    nonce: nonce+1,
                    genesisHash: api.genesisHash,
                    blockHash: api.genesisHash,
                    runtimeVersion: api.runtimeVersion,
                    version: api.extrinsicVersion
                });
                const extrinsicPayload = api.createType('ExtrinsicPayload', signingPayload.toPayload(), { version: api.extrinsicVersion })
                const u8a = extrinsicPayload.toU8a({ method: true })
                console.log("payload:", u8a);
                console.log("signing payload", signingPayload)
                const encoded = u8a.length > 256
                    ? blake2AsU8a(u8a)
                    : u8a;
                console.log("payloadHash", encoded.toString())
                console.log("something", u8aToU8a(encoded).toString())
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
                await apiTx.send()
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

async function rpcToLocalNode(
        method,
        params = []
    ) {
        return fetch('http://1rpc.io/dot', {
            body: JSON.stringify({
                id: 1,
                jsonrpc: '2.0',
                method,
                params,
            }),
            headers: {
                'Content-Type': 'application/json',
            },
            method: 'POST',
        })
            .then((response) => response.json())
            .then(({ error, result }) => {
                if (error) {
                    throw new Error(
                        `${error.code} ${error.message}: ${JSON.stringify(error.data)}`
                    );
                }

                return result;
            });
}