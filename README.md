# ethereum p2p initial handshake

## Description

This is an implementation of the RLPx protocol as described [here](https://hackmd.io/@Nhlanhla/SJv3wnhMK#The-RLPx-Transport-Protocol).

## Test

To test execute "cargo run [id] [ip] [port]"  
For example:

```
 cargo run 4a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c907730b353caf0c7374b200da1e0e3dfef67edd9934318c73317520b1bcd2550 195.201.207.37 30303
```

output:

```
Target adress: 195.201.207.37:30303
Connected to target adress
Auth message send to target node

Hanshake completed succesfully
 Received MAC is valid!!!

Hello message from target node:
Hello { protocol_version: 5, client_version: "Geth/v1.11.6-stable-ea9e62ca/linux-amd64/go1.20.3", capabilities: [Capability { name: "eth", version: 66 }, Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(8c906ef21582acf4097f02c97f91efce7c9252f1a63662ce9c8aea01a4843d4a5025cd1b0b521733c7184393d9ed67efdfe3e0a10d204b37c7f0ca53b3307790) }
```

```
 cargo run 5982f04beb8ccffd51d37ca87ac83a41a813a0bf2c752049e3912729ebee3cfd28ca7703b8d695746fbc3607fadbd1992f1f392750cd9173dc5327e10ca596cc 13.212.31.61 30303
```

output:

```
Target adress: 13.212.31.61:30303
Connected to target adress
Auth message send to target node

Hanshake completed succesfully
 Received MAC is valid!!!

Hello message from target node:
Hello { protocol_version: 5, client_version: "Geth/v1.11.6-stable/linux-amd64/go1.20.3", capabilities: [Capability { name: "eth", version: 66 }, Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(fd3ceeeb292791e34920752cbfa013a8413ac87aa87cd351fdcf8ceb4bf08259cc96a50ce12753dc7391cd5027391f2f99d1dbfa0736bc6f7495d6b80377ca28) }
```

### Logger
To enable logger:

```
export RUST_LOG=[level]
```

## Note

IDs, IPs, and corresponding ports were received from [ethernodes](https://ethernodes.org/nodes).
