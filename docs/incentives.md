# BitVM Protocol Node Incentives and Cost Specification

---

## Global Parameters

* `FEE_RATE_L1`: Bitcoin fee rate (unit: sats / vbyte)
* Layer-1 (L1, Bitcoin) asset unit: BTC / sats
* Layer-2 (L2, GOAT Network) asset unit: stakeToken (pegBTC)

---

## Challenger

### Initiating a Challenge

* A challenge transaction is broadcast on Layer-1.
* Layer-1 transaction fee cost: `CHALLENGE_TX_VBYTES * FEE_RATE_L1`.
* A bond must be paid on Layer-1: `CHALLENGE_BOND`.

  * The bond is paid directly to the challenged operator.

### Disprove

* After a challenge is initiated, a disprove transaction must be broadcast.
* The initiator of the disprove does not need to be the same entity as the challenge initiator.
* Layer-1 transaction fee cost range:

  * `DISPROVE_TX_VBYTES_MIN * FEE_RATE_L1`
  * `DISPROVE_TX_VBYTES_MAX * FEE_RATE_L1`

### Rewards Upon Success (Layer-2)

* If the challenge succeeds:

  * The challenge initiator receives `CHALLENGE_REWARD_L2`.
  * The disprove initiator receives `DISPROVE_REWARD_L2`.

---

## Watchtower

* Responsible for monitoring operator behavior during the challenge window.
* Must broadcast a `WATCHTOWER_PROOF_TX`.
* Layer-1 transaction fee cost: `WATCHTOWER_TX_VBYTES * FEE_RATE_L1`.

---

## Committee / Relayer

### Committee

* Under normal circumstances, no transactions need to be sent.

### Relayer

* Committee members may be configured as relayers.
* Relayers submit graph-related transactions to Layer-2.
* Relayers receive incentives based on the number of submissions.
* Reward per submission: `RELAYER_REWARD_L2`.

---

## Pegin / Pegout Fees

### Pegin

* When initiating a pegin, the user must pay a pegBTC fee.
* Fee rate: `PEGIN_FEE_RATE`.
* The fee is deducted from the pegin pegBTC amount.

### Pegout

* When executing a pegout, the operator must pay a pegBTC fee.
* Fee rate: `PEGOUT_FEE_RATE`.
* After a successful pegout, the operator receives a pegBTC reward.
* Reward rate: `PEGOUT_REWARD_RATE`.

---

## Operator

### Layer-2 Staking

* Operators must stake on Layer-2.

* Minimum required stake: `OPERATOR_STAKE_MIN`.

* Protocol constraints:

  * A single operator may execute at most **two pegouts (graphs)** concurrently.
  * Once any graph is successfully disproved:

    * The operator is prohibited from initiating new pegouts.

* Therefore, the protocol requires:

  * `OPERATOR_STAKE_MIN >= 2 × OPERATOR_SLASH_AMOUNT`,
  * `OPERATOR_SLASH_AMOUNT >= CHALLENGE_BOND + DISPROVE_TX_VBYTES_MAX * FEE_RATE_L1`
  * to ensure that even in the worst case (two graphs being disproved simultaneously), sufficient stake remains to be slashed.

### Malicious Behavior Penalties

* If an operator behaves maliciously and is successfully challenged and disproved:

  * A fixed amount of stakeToken, `OPERATOR_SLASH_AMOUNT`, is deducted from the operator’s current stake.
  * The slashed stakeToken is distributed to the challenge initiator and the disprove initiator.
  * Any remaining portion is retained in the contract.

### Layer-1 Fee Prefunding (Per Graph)

* For each graph, the operator must pre-fund Layer-1 transaction fees:

  * `GRAPH_BOND_L1`.
* Fees are later refunded depending on the execution path.

| Action | Additional Layer-1 Fee          |
| ------ | ------------------------------- |
| take1  | `TAKE1_TX_VBYTES * FEE_RATE_L1` |
| skip   | `SKIP_TX_VBYTES * FEE_RATE_L1`  |

---

## Graph and Multi-Operator Mechanism

* Each pegin may have multiple operators generating graphs in parallel.
* Ultimately, only one operator can successfully execute `take1`.
* All other operators must execute `skip`.

---

## Testnet Parameter Configuration (Current)

### Economic and Fee Parameters

```text
FEE_RATE_L1 = 1 sats/vbyte

CHALLENGE_BOND = 0.01 BTC

CHALLENGE_REWARD_L2 = 0.0125 pegBTC
DISPROVE_REWARD_L2 = 0.0025 pegBTC

RELAYER_REWARD_L2 = not set

OPERATOR_STAKE_MIN = 0.06 pegBTC
OPERATOR_SLASH_AMOUNT = 0.03 pegBTC

GRAPH_BOND_L1 = 10_000 sats

PEGIN_FEE_RATE = 0.5%
PEGOUT_FEE_RATE = not set
PEGOUT_REWARD_RATE = 0.3%
```

### Transaction Size Parameters (Testnet)

```text
CHALLENGE_TX_VBYTES = 1_000

DISPROVE_TX_VBYTES_MIN = 500
DISPROVE_TX_VBYTES_MAX = 1_000_000

WATCHTOWER_TX_VBYTES = 4_000

TAKE1_TX_VBYTES = 2_000
SKIP_TX_VBYTES = 300
```

