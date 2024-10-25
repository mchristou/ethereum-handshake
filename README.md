# ethereum p2p initial handshake

## Description

This is an implementation of the RLPx protocol as described [here](https://hackmd.io/@Nhlanhla/SJv3wnhMK#The-RLPx-Transport-Protocol).

## Test

To test execute "cargo run [id] [ip] [port]"  
For example:

```
cargo run c6e7a6a1934fa4bcad9bd448afd490661c6f2186fd07fe68ae76805bedbe0631594ed320f9a420cdcfe8510079135c1496f41a6b9c7c6f452dc7ebd640356f47 40.160.12.24 30303
```

output:

```
[2024-10-25T05:36:59Z INFO  ethereum_handshake] Target address: 40.160.12.24:30303
[2024-10-25T05:37:00Z INFO  ethereum_handshake] Connected to target address
[2024-10-25T05:37:00Z INFO  ethereum_handshake] Auth message sent to target node
[2024-10-25T05:37:00Z INFO  ethereum_handshake::handshake]
    Received MAC is valid!!!

[2024-10-25T05:37:00Z INFO  ethereum_handshake::codec] Hello message from target node:
    Hello { protocol_version: 5, client_version: "Geth/v1.13.14-stable/linux-amd64/go1.22.4", capabilities: [Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: [198, 231, 166, 161, 147, 79, 164, 188, 173, 155, 212, 72, 175, 212, 144, 102, 28, 111, 33, 134, 253, 7, 254, 104, 174, 118, 128, 91, 237, 190, 6, 49, 89, 78, 211, 32, 249, 164, 32, 205, 207, 232, 81, 0, 121, 19, 92, 20, 150, 244, 26, 107, 156, 124, 111, 69, 45, 199, 235, 214, 64, 53, 111, 71] }
[2024-10-25T05:37:00Z INFO  ethereum_handshake::handshake]
    Received MAC is valid!!!

[2024-10-25T05:37:00Z INFO  ethereum_handshake::codec] Status message received: Status { version: 68, networkid: 1, td: 58750003716598352816469, blockhash: [215, 103, 106, 179, 199, 128, 92, 254, 141, 113, 203, 53, 166, 119, 170, 243, 207, 222, 10, 227, 48, 218, 231, 80, 107, 73, 175, 212, 125, 88, 50, 40], genesis: [212, 229, 103, 64, 248, 118, 174, 248, 192, 16, 184, 106, 64, 213, 245, 103, 69, 161, 24, 208, 144, 106, 52, 230, 154, 236, 140, 13, 177, 203, 143, 163], forkid: ForkId { hash: 2671583828, next: 0 } }
```

```
cargo run 1e2cffe237a53d33efe71f6661cb46f8404a590e0ff2131525a901480a49dc7f20d7ffb5c4e5a84664021d439b5daff7076e7ae2742d676ee3465e1929639cd6 158.41.53.148 30404
```

output:

```
[2024-10-25T05:43:06Z INFO  ethereum_handshake] Connecting to target address: 158.41.53.148:30404
[2024-10-25T05:43:07Z INFO  ethereum_handshake] Connected to target address
[2024-10-25T05:43:07Z INFO  ethereum_handshake] Auth message sent to target node
[2024-10-25T05:43:07Z INFO  ethereum_handshake::handshake]
    Received MAC is valid!!!

[2024-10-25T05:43:07Z INFO  ethereum_handshake::codec] Hello message from target node:
    Hello { protocol_version: 5, client_version: "Nethermind/v1.29.1+dfea5240/linux-x64/dotnet8.0.10", capabilities: [Capability { name: "eth", version: 66 }, Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "nodedata", version: 1 }], port: 30404, id: [30, 44, 255, 226, 55, 165, 61, 51, 239, 231, 31, 102, 97, 203, 70, 248, 64, 74, 89, 14, 15, 242, 19, 21, 37, 169, 1, 72, 10, 73, 220, 127, 32, 215, 255, 181, 196, 229, 168, 70, 100, 2, 29, 67, 155, 93, 175, 247, 7, 110, 122, 226, 116, 45, 103, 110, 227, 70, 94, 25, 41, 99, 156, 214] }
[2024-10-25T05:43:07Z INFO  ethereum_handshake::handshake]
    Received MAC is valid!!!

[2024-10-25T05:43:07Z INFO  ethereum_handshake::codec] Disconnect message from target node:
    Disconnect { reason: 4 }
```

### Logger
To enable logger:

```
export RUST_LOG=[level]
```

## Note

IDs, IPs, and corresponding ports were received from [ethernodes](https://ethernodes.org/nodes).
