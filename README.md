# JavaScript Data Primitives Library for Hoosat

Based on the popular [Bitcore library](https://github.com/bitpay/bitcore) developed by BitPay for the Bitcoin, htn-core library provides primitives for interfacing with the Hoosat network.

## Get Started

```sh
git clone git@github.com:aspectron/htn-core-lib
```

Adding htn-core to your app's `package.json`:

```json
"dependencies": {
    "aspectron/htn-core-lib": "*"
}
```

## Hoosat adaptation

htn-core library provides primitives such as Transaction and UTXO data structures customized for use with the next-generation high-performance Hoosat network.

## Documentation

The complete docs are hosted here: [bitcore documentation](https://github.com/bitpay/bitcore). There's also a [bitcore API reference](https://github.com/bitpay/bitcore/blob/master/packages/bitcore-node/docs/api-documentation.md) available generated from the JSDocs of the project, where you'll find low-level details on each bitcore utility.

## Building the Browser Bundle

To build a htn-core-lib full bundle for the browser:

```sh
gulp browser
```

This will generate files named `htn-core-lib.js` and `htn-core-lib.min.js`.

You can also use our pre-generated files, provided for each release along with a PGP signature by one of the project's maintainers. To get them, checkout the [releases](https://github.com/bitpay/bitcore/blob/master/packages/bitcore-lib/CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/Contributing.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Bitcore - Copyright 2013-2019 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.  
htn-core - Copyright 2020 ASPECTRON Inc.
