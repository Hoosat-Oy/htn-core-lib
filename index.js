"use strict";

const secp256k1 = require("secp256k1-wasm");
const blake2b = require("blake2b-wasm");

var hoosatcore = module.exports;

hoosatcore.secp256k1 = secp256k1;

// module information
hoosatcore.version = "v" + require("./package.json").version;
hoosatcore.versionGuard = function (version) {
  if (version !== undefined) {
    var message =
      "More than one instance of hoosatcore-lib found. " +
      "Please make sure to require hoosatcore-lib and check that submodules do" +
      " not also include their own hoosatcore-lib dependency.";
    throw new Error(message);
  }
};
hoosatcore.versionGuard(global._hoosatcoreLibVersion);
global._hoosatcoreLibVersion = hoosatcore.version;

const wasmModulesLoadStatus = new Map();
hoosatcore.wasmModulesLoadStatus = wasmModulesLoadStatus;
wasmModulesLoadStatus.set("blake2b", false);
wasmModulesLoadStatus.set("secp256k1", false);

const setWasmLoadStatus = (mod, loaded) => {
  //console.log("setWasmLoadStatus:", mod, loaded)
  wasmModulesLoadStatus.set(mod, loaded);
  let allLoaded = true;
  wasmModulesLoadStatus.forEach((loaded, mod) => {
    //console.log("wasmModulesLoadStatus:", mod, loaded)
    if (!loaded) allLoaded = false;
  });

  if (allLoaded) hoosatcore.ready();
};

blake2b.ready(() => {
  setWasmLoadStatus("blake2b", true);
});

secp256k1.onRuntimeInitialized = () => {
  //console.log("onRuntimeInitialized")
  setTimeout(() => {
    setWasmLoadStatus("secp256k1", true);
  }, 1);
};

secp256k1.onAbort = (error) => {
  console.log("secp256k1:onAbort:", error);
};
const deferred = () => {
  let methods = {};
  let promise = new Promise((resolve, reject) => {
    methods = { resolve, reject };
  });
  Object.assign(promise, methods);
  return promise;
};
const readySignal = deferred();

hoosatcore.ready = () => {
  readySignal.resolve(true);
};
hoosatcore.initRuntime = () => {
  return readySignal;
};

// crypto
hoosatcore.crypto = {};
hoosatcore.crypto.BN = require("./lib/crypto/bn");
hoosatcore.crypto.ECDSA = require("./lib/crypto/ecdsa");
hoosatcore.crypto.Schnorr = require("./lib/crypto/schnorr");
hoosatcore.crypto.Hash = require("./lib/crypto/hash");
hoosatcore.crypto.Random = require("./lib/crypto/random");
hoosatcore.crypto.Point = require("./lib/crypto/point");
hoosatcore.crypto.Signature = require("./lib/crypto/signature");

// encoding
hoosatcore.encoding = {};
hoosatcore.encoding.Base58 = require("./lib/encoding/base58");
hoosatcore.encoding.Base58Check = require("./lib/encoding/base58check");
hoosatcore.encoding.BufferReader = require("./lib/encoding/bufferreader");
hoosatcore.encoding.BufferWriter = require("./lib/encoding/bufferwriter");
hoosatcore.encoding.Varint = require("./lib/encoding/varint");

// utilities
hoosatcore.util = {};
hoosatcore.util.buffer = require("./lib/util/buffer");
hoosatcore.util.js = require("./lib/util/js");
hoosatcore.util.preconditions = require("./lib/util/preconditions");
hoosatcore.util.base32 = require("./lib/util/base32");
hoosatcore.util.convertBits = require("./lib/util/convertBits");
hoosatcore.setDebugLevel = (level) => {
  hoosatcore.util.js.debugLevel = level;
};

// errors thrown by the library
hoosatcore.errors = require("./lib/errors");

// main bitcoin library
hoosatcore.Address = require("./lib/address");
hoosatcore.Block = require("./lib/block");
hoosatcore.MerkleBlock = require("./lib/block/merkleblock");
hoosatcore.BlockHeader = require("./lib/block/blockheader");
hoosatcore.HDPrivateKey = require("./lib/hdprivatekey.js");
hoosatcore.HDPublicKey = require("./lib/hdpublickey.js");
hoosatcore.Networks = require("./lib/networks");
hoosatcore.Opcode = require("./lib/opcode");
hoosatcore.PrivateKey = require("./lib/privatekey");
hoosatcore.PublicKey = require("./lib/publickey");
hoosatcore.Script = require("./lib/script");
hoosatcore.Transaction = require("./lib/transaction");
hoosatcore.URI = require("./lib/uri");
hoosatcore.Unit = require("./lib/unit");

// dependencies, subject to change
hoosatcore.deps = {};
hoosatcore.deps.bnjs = require("bn.js");
hoosatcore.deps.bs58 = require("bs58");
hoosatcore.deps.Buffer = Buffer;
hoosatcore.deps.elliptic = require("elliptic");
hoosatcore.deps._ = require("lodash");

// Internal usage, exposed for testing/advanced tweaking
hoosatcore.Transaction.sighash = require("./lib/transaction/sighash");
