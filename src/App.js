import {WagmiConfig, createClient, useSignMessage, mainnet} from 'wagmi'
import { getDefaultProvider } from 'ethers'
import { useAccount, useConnect, useDisconnect } from 'wagmi'
import { InjectedConnector } from 'wagmi/connectors/injected'
import Web3 from 'web3';
import {ApiPromise, Keyring, WsProvider} from '@polkadot/api';
import {
    blake2AsHex,
    cryptoWaitReady, secp256k1Compress,
    evmToAddress, encodeAddress,
} from '@polkadot/util-crypto';
import {
    construct, createMetadata, getRegistry,
    methods,
} from '@substrate/txwrapper-polkadot';
import {EXTRINSIC_VERSION} from "@polkadot/types/extrinsic/v4/Extrinsic";
import {arrayify, computeAddress, keccak256, recoverPublicKey, splitSignature, toUtf8Bytes} from "ethers/lib/utils";
import {fromRpcSig, toCompactSig} from "ethereumjs-util";
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
                console.log("signed by", publicKey)
                const address=  computeAddress(publicKey)
                console.log("address: ",address)

                //sign message using normal ecdsa
                let normalSig = ec.sign(msgHash, keypair.getPrivate("hex"), "hex");
                console.log("normal sig", {r:normalSig.r.toString(), s: normalSig.s.toString()})

                //create a wrapper transaction
                await cryptoWaitReady();
                const provider= new WsProvider("wss://polkadot.api.onfinality.io/public-ws")
                const api = await ApiPromise.create({provider})
                    // Construct a balance transfer transaction offline.
                    // To construct the tx, we need some up-to-date information from the node.
                    // `txwrapper` is offline-only, so does not care how you retrieve this info.
                    // In this tutorial, we simply send RPC requests to the node.
                const { block } = (await api.rpc.chain.getBlock()).toJSON()
                console.log("block", block)
                const blockHash = (await api.rpc.chain.getBlockHash()).toJSON()
                console.log("block hash", blockHash)
                const genesisHash = (await api.rpc.chain.getBlockHash(0)).toJSON()
                console.log("genesis hash", genesisHash)
                const metadataRpc = (await api.rpc.state.getMetadata()).toJSON()
                console.log("metadata", metadataRpc)
                const { specVersion, transactionVersion, specName } = (await api.rpc.state.getRuntimeVersion()).toJSON()
                console.log("runtime versions", { specVersion, transactionVersion, specName })
                const registry = getRegistry({
                    chainName: 'Polkadot',
                    specName,
                    specVersion,
                    metadataRpc,
                });
                console.log("here")
                const compressPubicKey= secp256k1Compress(arrayify(publicKey))
                console.log({compressPubicKey})
                const hash = blake2AsHex(compressPubicKey);
                console.log("hash", hash)
                const substrateAdder= encodeAddress(hash)
                console.log("substrate addr", substrateAdder);

                const unsigned = methods.balances.transferKeepAlive(
                    {
                        value: '10000000000',
                        dest: '14E5nqKAp3oAJcmzgZhUD2RcptBeUBScxKHgJKU4HPNcKVf3', // Bob
                    },
                    {
                        address:  substrateAdder,
                        blockHash,
                        blockNumber: registry
                            .createType('BlockNumber', block.header.number)
                            .toNumber(),
                        eraPeriod: 64,
                        genesisHash,
                        metadataRpc,
                        nonce: 0, // Assuming this is Alice's first tx on the chain
                        specVersion,
                        tip: 0,
                        transactionVersion,
                    },
                    {
                        metadataRpc,
                        registry,
                    }
                );
                console.log("here2")
                const signingPayload = construct.signingPayload(unsigned, { registry });
                registry.setMetadata(createMetadata(registry, metadataRpc));
                const extrinsicPayload = registry
                    .createType('ExtrinsicPayload', signingPayload, {
                        version: EXTRINSIC_VERSION,
                    })
                const encode = blake2AsHex(extrinsicPayload.toU8a())
                let signatureEcdsa = await web3.eth.sign(encode, accounts[0]);
                console.log("signature ecdsa", signatureEcdsa)
                console.log("signature buffer", toUtf8Bytes(signatureEcdsa).length)

                //verify signature

                //create multi-signature
                const signature = api.createType("MultiSignature", {ecdsa: signatureEcdsa})
                console.log("signature", signature.isEcdsa)
                const tx = construct.signedTx(unsigned, signature.toHex(), {
                    metadataRpc,
                    registry,
                });
                const actualTxHash = await api.rpc.author.submitExtrinsic(tx);
                const addr= web3.eth.accounts.recover()

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