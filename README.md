# GOAT Bitvm2 Node
A universal node for Operator, Challenger and Covenant Signer.

## Tutorial

See [Node](node/README.md).

## Architecture Overview

```mermaid
stateDiagram-v2
    [*] --> RPCServer 

    state RPCServer {
        state Middleware {
            [*] --> Identity
            Identity --> behaviour
            [*] --> MetricServer 
        }
        behaviour --> Store
        behaviour --> MessageHandler
    }
       
    state MessageHandler {
        [*] --> message 
        message --> Actor 
    }
    state Actor {
        [*] --> Federation 
        [*] --> Operator 
        [*] --> Challenger
        [*] --> More... 
    }
    
    state Identity {
        [*] --> client
        [*] --> p2p(KAD)
        [*] --> musig2
    }

    state Store {
        [*] --> payload 
        payload --> LocalDB(Mem)
        payload --> IPFS
    }
```

## Roles

There are three main roles in this protocol, Federation, Operator and Challenger.

| Role   | Functions                                                                                                                                                                                                                                                                                  |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Federation | N-of-n signers for the presign transactions                                                                                                                                                                                                                                                |
| Operator | Anyone can be an operator. <br>1. Exchange PeggleBTC to native BTC with users <br>2. Kickoff the reimbursement from Federation <br> 3. Generate the preimage of the hash time lock to each watchtower <br>4. Exchange PegBTC to BTC with end-user via AtomicSwap                           |
| Challenger | Anyone can be a challenger <br>1. Verify the valid of the reimbursement from operators offchain <br>2. Submit the challenge transaction on Bitcoin to force the kick off to unhappy path                                                                                                   
| Watchtower | A special kind of challenger, selected from the Sequencer candidates, maintains the longest chain headers and spends the Watchtower output of the Kickoff transaction.                                                                                                                     
| Verifier | Another kind of challenger. Once the kickoff is on the unhappy path, and the operator unveils all the execution trace(Circuit F below), verify finds the flow in the execution trace, and can spend the UTXO from Assert transaction, and stop the operator to continue the reimbursement. 

## BitVM2 protocol

### Peg-in
<!-- https://mermaid.js.org/syntax/stateDiagram.html#state-diagrams -->

```mermaid
sequenceDiagram
    participant U as User
    participant F as Federation
    participant O as Operator
    participant B as Bitcoin Network
    participant L2 as Layer 2

    U->>B: Broadcast incomplete Peg-in tx
    F->>All: Generate & broadcast keypair + Musig2 Nonce
    O->>F: Generate BitVM2 tx graph & Presign Challenge 
    F->>All: Presign Take1/Take2/Disprove/Assert tx
    U->>B: Sign & broadcast pegin tx
    Note over B: Transaction confirmation
    F->>L2: Submit pegin txid & graph info
```

**Message Type**

### Kick-Off

```mermaid
sequenceDiagram
    participant O as Operator
    participant B as Bitcoin Network
    participant L2 as Layer 2

    O->>L2: initWithdraw tx (lock pegBTC & UTXO)
    Note over L2: Broadcast initWithdraw txid
    O->>B: Sign & broadcast Kickoff tx
    Note over B: Transaction confirmation
    O->>L2: Submit Kickoff tx
    Note over L2: Burn locked pegBTC & update state
```

**Message Type**

### Claim
```mermaid
sequenceDiagram
    participant O as Operator
    participant B as Bitcoin Network
    participant A as All Roles
    participant L2 as Layer 2

    Note over O: After Kickoff, wait for challenge period
    O->>B: Sign & broadcast Take-1 tx
    O->>A: Broadcast Take-1 tx
    Note over A: Update graph state
    O->>L2: Submit Take-1 tx
    Note over L2: Update contract state
```

**Message Type**

### Challenge

```mermaid
sequenceDiagram
    participant C as Challenger
    participant B as Bitcoin Network
    participant O as Operator
    participant L2 as Layer 2
    participant A as All Roles

    C->>B: Monitor unused Kickoff txids
    Note over B: Kickoff transaction confirmed
    C->>L2: Check initWithdraw validity
    C->>B: If invalid, broadcast Challenge tx
    C->>O: Send challenge notification
    O->>B: Generate & broadcast Assert tx with proof
    O->>C: Send response message
    C->>B: Verify proof from Assert witness
    alt Proof incorrect
        C->>B: Broadcast Disprove tx
        C->>A: Broadcast Disprove tx
        C->>L2: Submit Disprove tx
    else Proof correct
        Note over C: Challenge failed
        O->>B: After challenge period, broadcast Take-2
        O->>A: Broadcast Take-2
        O->>L2: Submit Take-2
    end
    Note over L2: Update state
```

**Message Type**

## Node 

### Run a node

```bash
./target/debug/goat-bitvm2-node
```
It should print out the address to listen on.

In another console, run 
```bash
./target/debug/goat-bitvm2-node /ip4/127.0.0.1/tcp/50022
```
Replace the peer address with above.

#### Operation
**Requirement** 

Federation Member: need approval from all federation members

Challenger: anyone can be a challenger

Operator: anyone who holds PeggledBTC can be an operator 

**Operation**

1. Generate identity
2. Configure the bootnode and launch the node

**Unjoin**

#### Identity and Authentication

Generate the identity by cli.

P2P: ed25519

Federation n-of-n: musig2 (secp256k1)  

### Store

**Local Store**: Sqlite
**Memory Store**

**Scheme**

| Field name       | Description                   | Field type      |
|------------------|-------------------------------|-----------------| 
| Peg-in txid      | Peg-in Bitcoin transaction id | bytes: 32-byte  |
| Covenant address | BitVM2 covenant address       | bytes: 64-byte  |
| Amount           | The amount pegged-in          | integer: 32-bit | 
| Operator         | The operator's bitcoin address | string          | 
| Step             | Current step                  | integer: 8-bit  | 
| BitVM2 instance  | BitVM2 transaction graph      | string          | 


### Middleware

Define all the behaviours and [metrics server](https://github.com/libp2p/rust-libp2p/blob/e1bba263070194282cad48f07fb4aa0c87d03b55/examples/metrics/src/http_service.rs#L32).

* Peer discovery protocol: KAD
* Basic behaviours
* Custom behaviours 
