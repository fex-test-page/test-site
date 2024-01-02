
importScripts("https://unpkg.com/comlink/dist/umd/comlink.js");
importScripts("./webworker-utils.js");

async function remoteGenerateMiningMessage(network, txId, unlock, lock, difficulty, cb) {
  const wallet = {
    "mainnet": ["d8a8fe8d3ce4260d28ec4b8e9554ee1a2d4c96234e5a4a57efbdf8d3cd596d49", "03fe2bd8a959c7c9193c9ae3f5ea5c4919190328341e8dfd1c241cba6c0ae1b187"],
    "testnet": ["1e987f098a31bc99865526282e90d37a4baf55c29c5e4748126274d359cceac6", "025c278a40a12d4b8a01ea4bc21dde25d5527ce979e68ea7c2d61efe6f92844a75"]
  }
  const priv = libauth_1.hexToBin(wallet[network][0])
  const pubkey = libauth_1.hexToBin(wallet[network][1])
  for (let i = 0; i < Number.MAX_SAFE_INTEGER; i++) {
    const msg = encodeLE8(i) + reverseHexBytes(txId) + unlock + lock;
    const messageHash = sha256.hash(hexToBin(msg));
    const sig = secp256k1.signMessageHashSchnorr(priv, messageHash);
    const ok = secp256k1.verifySignatureSchnorr(sig, pubkey, messageHash);
    if (!ok) {
      throw new Error('verify signature failed');
    }

    const hash = binToHex(ripemd160.hash(sig));
    const number = decodeLE4(hash.slice(0, 8))
    if (Math.abs(number) < Math.floor(MAX_DIFFICULTY / difficulty)) {
      return [i, msg, binToHex(sig), binToHex(pubkey)];
    }

    if ((i + 1) % 1000 === 0 && cb) {
      await cb(i + 1);
    }
  }

  throw new Error('try generate signature failed');
}

Comlink.expose(remoteGenerateMiningMessage);