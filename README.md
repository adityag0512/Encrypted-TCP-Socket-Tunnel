# Encrypted Tunnel System

A VPN-like encrypted tunneling system built in C++. The client and server communicate over a TCP connection where all traffic is encrypted end-to-end using AES-256-GCM.
---

## What it does

When two machines communicate over a network, anyone sitting between them can read the data (this is called a man-in-the-middle). A tunnel solves this by wrapping every message in encryption before it leaves your machine and unwrapping it only at the other end.

This project implements that tunnel from scratch:

- The **client** takes your message, encrypts it, wraps it in a custom binary packet, and sends it over TCP to the server.
- The **server** receives the packet, verifies it hasn't been tampered with, decrypts it, and sends an encrypted reply back.
- Anyone sniffing the network between them sees only random-looking bytes.

The current implementation is a working echo tunnel - the server receives your message and echoes it back. 

---

## Project structure

```
vpn_tunnel/
├── common/
│   ├── crypto.hpp          # AES-256-GCM encryption and decryption (via OpenSSL)
│   ├── protocol.hpp        # Binary packet format: header layout, read/write helpers
│   ├── socket_utils.hpp    # Reliable send_all / recv_all / send_packet / recv_packet
│   └── logger.hpp          
├── server/
│   └── server.cpp          # Listens for clients, spawns a thread per connection
├── client/
│   └── client.cpp          # Connects to server, CLI to send messages and view stats
└── Makefile
```

The four files under `common/` are shared between both programs. Both `server.cpp` and `client.cpp` `#include` them directly - there is no separate library build step.

---


Every packet on the wire follows this exact layout:

```
[ Magic 4B | Type 1B | Length 4B | IV 12B | Auth Tag 16B | Ciphertext NB ]
```

- **Magic** (`0xCAFEBABE`) - rejects packets that don't belong to this protocol
- **Type** - DATA, PING, PONG, or BYE
- **Length** - tells the receiver exactly how many bytes to read next (TCP has no built-in message boundaries)
- **IV** - a fresh random 12-byte value generated per message so identical plaintext encrypts differently every time
- **Auth tag** - 16 bytes produced by GCM that prove the ciphertext wasn't modified in transit; decryption fails loudly if it doesn't match

---

## Encryption

The project uses **AES-256-GCM** via the OpenSSL EVP interface.

- **AES-256** - 256-bit symmetric key; both sides must share the same key (passed as a CLI argument)
- **GCM mode** - provides both confidentiality (encryption) and integrity (the auth tag); no separate MAC needed
- **Fresh IV per message** - generated with `RAND_bytes()` and prepended to the payload so replay and pattern attacks don't work

A wrong key or tampered ciphertext causes `EVP_DecryptFinal_ex` to return an error. The code catches this and closes the connection immediately.

---

## Threading model

**Server** runs three kinds of threads simultaneously:
- One **main thread** - stuck in `accept()` waiting for new clients
- One **CLI thread** - reads your `status` / `quit` commands
- One **handle_client thread per connected client** - each runs its own recv → decrypt → reply loop

**Client** runs two threads:
- **Main thread** - reads your keyboard input and sends packets
- **receive_thread** - sits in a blocking `recv_packet()` waiting for replies from the server, prints them when they arrive


Shared data (the session map on the server) is protected by a `std::mutex`. The `running` flag shared between threads is `std::atomic<bool>` so reads and writes are thread-safe without a mutex.

---

## Build

**Prerequisites:** g++ with C++17 support, and the OpenSSL development headers.

```bash
# Ubuntu / Debian
sudo apt-get install build-essential libssl-dev
```

```bash
git clone https://github.com/adityag0512/Encrypted-TCP-Socket-Tunnel
cd vpn_tunnel
make
```

This produces two binaries: `server/server` and `client/client`.

---

## Running

Open two terminals.

**Terminal 1 — start the server:**
```bash
./server/server <port> <key>

# Example
./server/server 9000 mysecretkey
```

**Terminal 2 — connect the client:**
```bash
./client/client <server-ip> <port> <key>

# Local example
./client/client 127.0.0.1 9000 mysecretkey

# Remote example
./client/client 192.168.1.10 9000 mysecretkey
```

The key must match on both sides. If they differ, decryption will fail and the connection will be dropped.

---

## CLI reference

**Client commands:**

| Command | What it does |
|---|---|
| `<any text>` | Encrypts and sends the text through the tunnel; prints the server's reply |
| `ping` | Sends a PING packet; server replies with PONG to confirm it's alive |
| `stats` | Shows packets sent/received, total bytes, and average encrypt/decrypt time in µs |
| `quit` | Sends a graceful BYE packet, closes the connection, and exits |

**Server commands:**

| Command | What it does |
|---|---|
| `status` | Lists all active client sessions with their IP, port, and bytes sent/received |
| `quit` | Closes the listening socket and shuts the server down cleanly |

---



## What Phase 2 will add

Phase 1 proves the tunnel works - data goes in encrypted, comes out decrypted, and the connection is managed cleanly. Phase 2 makes the tunnel actually useful by routing real application traffic through it.

**Selective traffic routing** - instead of manually typing messages into the client CLI, a local proxy will intercept traffic from real applications (a browser, `curl`, etc.) on specific ports or for specific services (HTTP on port 80, HTTPS on 443) and forward it through the tunnel automatically. Applications won't need to know the tunnel exists.
