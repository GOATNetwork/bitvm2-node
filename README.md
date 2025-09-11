# GOAT Bitvm2 Node

A universal node for Operator, Challenger and Committee.

## Tutorial

See [Node](node/README.md).

## Roles

There are three main roles in this protocol, Committee, Operator, Challenger and Relayer.

| Role       | Functions                                                                                                                                                                                                                                                                                  |
|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Committee  | N-of-n signers for the presign transactions                                                                                                                                                                                                                                                |
| Operator   | Anyone can be an operator. <br>1. Exchange PeggleBTC to native BTC with users <br>2. Kickoff the reimbursement from Committee <br> 3. Generate the preimage of the hash time lock to each watchtower <br>4. Exchange PegBTC to BTC with end-user via AtomicSwap                            |
| Challenger | Anyone can be a challenger <br>1. Verify the valid of the reimbursement from operators offchain <br>2. Submit the challenge transaction on Bitcoin to force the kick off to unhappy path                                                                                                   |
| Watchtower | A special kind of challenger, selected from the Sequencer candidates, maintains the longest chain headers and spends the Watchtower output of the Kickoff transaction.                                                                                                                     |
| Verifier   | Another kind of challenger. Once the kickoff is on the unhappy path, and the operator unveils all the execution trace(Circuit F below), verify finds the flow in the execution trace, and can spend the UTXO from Assert transaction, and stop the operator to continue the reimbursement. |
| Relayer    | Operated by official nodes.<br>1.Provide bootnode services  <br>2 Supports asset transfer services between Layer 1 and Layer 2 of the BTVM2 system, including tracing L1 txn; calling and monitoring L2 gateway contract <br>3 Starting pegin processing.                                  |                                                                    |

## BitVM2 protocol

### BridgeIn

**PegIn**
<!-- https://mermaid.js.org/syntax/stateDiagram.html#state-diagrams -->

```mermaid
sequenceDiagram
    participant U as User
    participant R as Relayer
    participant F as Committee 
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    U->>B: Broadcast incomplete Peg-in tx
    U->>R: Send Peg-in Request
    R->>F: Generate Peg-in instance from user request
    F->>A: Generate & broadcast keypair + Musig2 Nonce
    O->>F: Generate BitVM2 tx graph & Presign Challenge 
    F->>A: Presign Take1/Take2/Disprove/Assert tx
    R->>U: Update Peg-in instance & store graph & notify user to broadcast Peg-in tx  through front end
    U->>B: Sign & broadcast  Peg-in tx
    B->>R: Monitor Peg-in tx Transaction confirmation
    R->>L2: Submit Peg-in tx_id & graph info & mint pegBTC
```

**Status**
The status of BridgeIn transitions from start to finish are listed below.
| Status | Description |
|--------------------|-------------------------------|
| Submitted | User submits BridgeIn request |
| OperatorPresigned | Operators finish presigning |
| CommitteePresigned | Committees finish presigning |
| L2Minted | Mint asset on Goat Chain |

```mermaid
---
title: BridgeIn Status
---
flowchart LR
    Submitted -- "Pegin tx input uxtos been spent" --> Discarded
    Submitted --> presiging
    subgraph presiging
        OperatorPresigned --> CommitteePresigned
    end
    presiging -- "timeout" --> PresignedFailed
    presiging --> user-submit
    subgraph user-submit
        PeginSent --> L2Minted
    end
    user-submit -- "any graph reach Take1/Take2" --> Reimbursed
```

### BridgeOut

**Kick-Off**

```mermaid
sequenceDiagram
    participant U as User
    participant R as Relayer
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    U->>L2: InitWithdraw tx (lock pegBTC & UTXO & mark graph could be used to kickoff the process)
    L2->>R: Get graph id & instance id related to initWithdraw tx
    R->>O: Notify O to sign & broadcast Kickoff tx
    O->>B: Sign & broadcast Kickoff tx
    B->>R: Monitor Kickoff tx confirmation
    R->>L2: Submit Kickoff tx to burn locked pegBTC & update contract state
    R->>A: Broadcast Kickoff tx confirmation
```

**Claim**

```mermaid
sequenceDiagram
    participant R as Relayer
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    R->>O: After Kickoff, notify O to do Take-1 action until challenge period timeout
    O->>B: Sign & broadcast Take-1 tx
    O->>A: Broadcast Take-1 tx confirmation
    B->>R: Monitor Take-1 tx confirmation & update graph state
    R->>L2: Submit Take-1 tx to update contract state
```

**Challenge**

```mermaid
sequenceDiagram
    participant R as Relayer
    participant C as Challenger
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2
    
    B->>R: Monitor Kickoff tx confirmation 
    R->>A: Broadcast Kickoff tx confirmation
    C->>L2: Check initWithdraw validity
    C->>B: If invalid, broadcast Challenge tx
    C->>A: Send challenge notification
    O->>B: Generate & broadcast Assert tx with proof
    B->>R: Monitor Assert tx confirmation
    R->>A: Assert tx confirmation
    C->>B: Verify proof from Assert witness
    alt Proof incorrect
        C->>B: Broadcast Disprove tx
        C->>A: Broadcast Disprove tx confirmation
        L2->>B: Monitor Disprove tx confirmation
        R->>L2: Submit Disprove tx to update contract state
    else Proof correct
        Note over C: Challenge failed
        R->>O: Notify O do Take-2 action until disproving period timeout
        O->>B: broadcast Take-2
        O->>A: Broadcast Take-2 tx confirmation
        L2->>R: Monitor Take-2 tx confirmation
        R->>L2: Submit Take-2 to update contract state
    end
```

**Status**
The status of BridgeOut transitions from start to finish are listed below.
| Status     | Description                                                                                                                                         |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Created    | BitVM2 Graph created                                                                                                                                |
| Presigned  | BitVM2 Graph presigned                                                                                                                              |
| L2Recorded | BitVM2 Graph record on Goat chain                                                                                                                   |
| Kickoff    | Operator broadcasts Kickoff Transaction to initiate the process.                                                                                    |
| Take1      | Happy Path: No challenge occurs. Operator obtains the assert. Relayer records it on Goat Chain                                                      |
| Challenge  | Challenger broadcasts Challenge Transaction to contest the step.                                                                                    |
| Assert     | Operator broadcasts Assert Transaction in response to the challenge.                                                                                |
| Disproved  | Challenger successfully broadcasts Disprove Transaction. Relayer records it on Goat Chain.                                                          |
| Take2      | UnHappy Path: Challenger does not broadcast Disprove Transaction. Operator obtains the assert on the unhappy path. Relayer records it on Goat Chain |

```mermaid
---
title BridgeOut status
---
flowchart
LR
	subgraph bridge-in
	  Created --> Presigned
	  Presigned -- pushOperatorData-L2 --> L2Recorded
  end
  bridge-in --> bridge-out
  subgraph bridge-out
	  OperatorDataPushed -- <i><b>Happy path</b></i><br>1.<b>operator</b>:initWithdraw(L2).<br>2.<b>operator</b>:send Kickoff Transaction(L1).<br>3.<b>relayer</b>:proceedWithdraw(L2) --> Kickoff
	  OperatorDataPushed --<i><b>Unhappy path</i></b><br>1.<b>operator</b>:send Kickoff Transaction(L1).<br>2.<b>relayer</b>:proceedWithdraw(L2) --> Kickoff
	  Kickoff--<i><b>Happy path</b></i><br>1.take1 time lock
expires, <b>operator</b>:send Take1 Transaction(L1).<br>2.<b>relayer</b>:finishWithdrawHappyPath(L2) --> Take1
	  Kickoff--<i><b>Unhappy way</b></i><br><b>challenger</b>send Chanllege Transaction(L1) --> Challenge
		Challenge--<i><b>publish proof</b></i><br><b>operator</b>: send Assert Txn(L1), contain proof-->Assert
		Challenge--<i><b>publish fraud proof</b></i><br><b>operator</b>: send Assert Txn(L1), contain fraud proof-->Assert
		Assert--<i><b>for fraud proof</b></i><br>1.<b>challenger</b> send Disprove Transaction(L1).<br>2.<b>relayer</b>:finishWithdrawDisprove(L2)-->Disproved
		Assert--<i><b>for valid proof</b></i><br>1.take2 time lock
expires, <b>operator</b> send Take2 Transaction(L1).<br>2.<b>relayer</b>:finishWithdrawUnhappyPath(L2)-->Take2
  end
  bridge-in -- instance reimbursed by other graph --> Obsoleted
  bridge-in -- instance Pegin tx input uxtos been spent --> Discarded
```

## Node

### Run a node

```bash
./target/debug/goat-bitvm2-node
```

It should print out the address to listen on.

In another console, run

```bash
./target/debug/goat-bitvm2-node --bootnodes /ip4/127.0.0.1/tcp/50022
```

Replace the peer address with above.

#### Operation

**Requirement**

Committee Member: need approval from all committee members

Challenger: anyone can be a challenger

Operator: anyone who holds PegBTC can be an operator

**Operation**

1. Generate identity
2. Configure the bootnode and launch the node

**Unjoin**

#### Identity and Authentication

Generate the identity by cli.

P2P: ed25519

Committee n-of-n: musig2 (secp256k1)

### Store

**Local Store**: Sqlite
**Memory Store**

**Scheme**

| Field name       | Description                    | Field type      |
|------------------|--------------------------------|-----------------|
| Peg-in txid      | Peg-in Bitcoin transaction id  | bytes: 32-byte  |
| Covenant address | BitVM2 covenant address        | bytes: 64-byte  |
| Amount           | The amount pegged-in           | integer: 32-bit |
| Operator         | The operator's bitcoin address | string          |
| Step             | Current step                   | integer: 8-bit  |
| BitVM2 instance  | BitVM2 transaction graph       | string          |

### Middleware

Define all the behaviours
and [metrics server](https://github.com/libp2p/rust-libp2p/blob/e1bba263070194282cad48f07fb4aa0c87d03b55/examples/metrics/src/http_service.rs#L32).

* Peer discovery protocol: KAD
* Basic behaviours
* Custom behaviours 
