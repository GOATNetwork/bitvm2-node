# BitVM2 Node RPC Service API Documentation

## Overview

This document describes the RPC service API endpoints for the BitVM2 Node. The service provides interfaces for managing
nodes, instances, and graphs in the BitVM2 network.

## Base URL

```
http://127.0.0.1:8080
```

## API Endpoints

### 1. Node Management

#### Create Node

relate struct

```rust
pub enum NodeActor {
    Committee,
    Operator,
    Challenger,
    Relayer,
    All,
}

pub enum NodeStatus {
    Online,
    Offline,
}

```

- **Endpoint**: `POST /v1/nodes`
- **Description**: Create a new node in the network
- **Request Body**:
  ```json
  {
    "peer_id": "string",
    "actor": "string",
    "eth_addr": "string",
    "btc_pub_key": "string",
    "socket_addr": "string"
  }
  ```
- **Response**:

```json
{
  "peer_id": "string",
  "actor": "string",
  "eth_addr": "string",
  "btc_pub_key": "string",
  "socket_addr": "string",
  "updated_at": "number",
  "created_at": "number"
}
```

#### Get Nodes

- **Endpoint**: `GET /v1/nodes`
- **Description**: Retrieve a list of nodes with optional filtering
- **Query Parameters**:
    - `actor`: Filter nodes by acotr (e.g., "Committee")
    - `goat_addr`: Filter nodes by goat address
    - `status`: Filter nodes by status (e.g., "Online", "Offline")
    - `offset`: Pagination offset
    - `limit`: Number of nodes to return
- **Response**:

```json
{
  "nodes": [
    {
      "peer_id": "string",
      "actor": "string",
      "eth_addr": "string",
      "btc_pub_key": "string",
      "socket_addr": "string",
      "updated_at": "number",
      "created_at": "number"
    }
  ],
  "total": "number"
}
```

#### Get Nodes Overview

- **Endpoint**: `GET /v1/nodes/overview`
- **Description**: Retrieve noders overview
- **Response**:

```json
{
  "nodes_overview": {
    "total": "number",
    "online_operator": "number",
    "offline_operator": "number",
    "online_challenger": "number",
    "offline_challenger": "number",
    "online_committee": "number",
    "offline_committee": "number",
    "online_relayer": "number",
    "offline_relayer": "number"
  }
}
```

### 2. Instance Management

relate struct

```rust
/// 1.instance.network:
pub enum InstanceNetwork {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network. (In future versions this will be combined
    /// into a single variant containing the version)
    Testnet,
    /// Bitcoin's testnet4 network. (In future versions this will be combined
    /// into a single variant containing the version)
    Testnet4,
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
}

/// 2. instance.bridge_path
pub enum InstanceBridgePath {
    BTCToPegBTC = 0,
    PegBTCToBTC = 1,
}

///3. instance status: contain two values: InstanceStatusBridgeInStatus or InstanceStatusBridgeOutStatus 
pub enum InstanceStatus {
    #[default]
    Submitted,
    Presigned, // includes operator and Committee presigns
    L1Broadcasted,
    L2Minted, // success
}

/// 4.instance.amount in bitcoin sat
```

#### Get Instance

- **Endpoint**: `GET /v1/instances/{id}`
- **Description**: Retrieve details of a specific instance
- **Path Parameters**:
    - `id`: Instance ID
- **Response**:

```json
{
  "instance_wrap": {
    "instance": {
      "instance_id": "string",
      "network": "string",
      "bridge_path": "number",
      "from_addr": "string",
      "to_addr": "string",
      "amount": "number",
      "status": "string",
      "goat_txid": "string",
      "btc_txid": "string",
      "pegin_txid": null,
      "input_uxtos": "json",
      "fee": "number",
      "created_at": "number",
      "updated_at": "number"
    },
    "confirmations": "number",
    "target_confirmations": "number",
    "utxo": [
      {
        "txid": "string",
        "vout": "number",
        "value": "number"
      }
    ]
  }
}
```

#### Filter Instances

- **Endpoint**: `GET /v1/instances`
- **Description**: Retrieve a list of instances with optional filtering
- **Query Parameters**:
    - `from_addr`: Filter by user address
    - `bridge_path`: select bridge path(e.g. 0: bridge in , 1 : bridge out)
    - `offset`: Pagination offset
    - `limit`: Number of instances to return
- **Response**: List of instances matching the criteria

```json
{
  "instance_wraps": [
    {
      "instance_wrap": {
        "instance": {
          "instance_id": "string",
          "network": "string",
          "bridge_path": "number",
          "from_addr": "string",
          "to_addr": "string",
          "amount": "number",
          "status": "string",
          "goat_txid": "string",
          "btc_txid": "string",
          "pegin_txid": null,
          "input_uxtos": "json",
          "fee": "number",
          "created_at": "number",
          "updated_at": "number"
        },
        "confirmations": "number",
        "target_confirmations": "number",
        "utxo": [
          {
            "txid": "string",
            "vout": "number",
            "value": "number"
          }
        ]
      }
    }
  ],
  "total": "number"
}
  ```

#### InstanceOverview Instances

- **Endpoint**: `GET /v1/instances/overview`
- **Description**: Retrieve instance overview
- **Response**: bridge in and bridge out info

```json
{
  "instances_overview": {
    "total_bridge_in_amount": "number",
    "total_bridge_in_txn": "number",
    "total_bridge_out_amount": "number",
    "total_bridge_out_txn": "number",
    "online_nodes": "number",
    "total_nodes": "number"
  }
}
  ```

### 3. Bridge Operations

#### Bridge In Transaction Prepare

- **Endpoint**: `POST /v1/instances/action/bridge_in_tx_prepare`
- **Description**: Prepare a bridge-in transaction
- **Request Body**:
  ```json
  {
    "instance_id": "string",
    "network": "string",
    "amount": "number",
    "fee_rate": "number",
    "utxo": [
      {
        "txid": "string",
        "vout": "number",
        "value": "number"
      }
    ],
    "from": "string",
    "to": "string"
  }
  ```
- **Response**:
  ```json
  {}
  ```

### 4. Graph Management

relate struct

```rust

///1.graph.status
pub enum GraphStatus {
    #[default]
    OperatorPresigned,
    CommitteePresigned,
    OperatorDataPushed,
    KickOffing,
    KickOff,
    Challenging,
    Challenge,
    Asserting,
    Assert,
    Take1,
    Take2,
    Disproving,
    Disprove,   // fail to reimbursement
    Reimbursed,
}

/// graph.bridge_path 

pub enum GraphBridgePath {
    BTCToPegBTC = 0,
    PegBTCToBTC = 1,
}

```

#### Create Graph

- **Endpoint**: `POST /v1/graphs`
- **Description**: Create a new graph
- **Request Body**:
  ```json
  {
    "instance_id": "string",
    "graph_id": "string"
  }
  ```
- **Response**:
  ```json
  {
    "instance_id": "string",
    "graph_id": "string",
    "graph_ipfs_unsigned_txns": "string"
  }
  ```

#### Get Graph

- **Endpoint**: `GET /v1/graphs/{id}`
- **Description**: Retrieve details of a specific graph
- **Path Parameters**:
    - `id`: Graph ID
- **Response**:
  ```json
  {
    "graph": {
        "graph_id": "string",
        "instance_id": "string",
        "amount": "number",
        "graph_ipfs_base_url": "string",
        "pegin_txid": "string",
        "status": "string",
        "kickoff_txid": "string",
        "challenge_txid": "string",
        "take1_txid": "number",
        "assert_init_txid": "number",
        "assert_commit_txids": "number",
        "assert_final_txid": "string",
        "take2_txid": "string",
        "disprove_txid": "string",
        "bridge_out_start_at": "number",
        "bridge_out_from_addr": "string",
        "bridge_out_to_addr":"string",
        "init_withdraw_txid": "string",
        "operator": "string",
        "raw_data": "string",
        "updated_at": "number",
        "created_at": "number"
    }
  }
  ```

#### Get Graphs

- **Endpoint**: `GET /v1/graphs`
- **Description**: Retrieve a list of graphs with optional filtering
- **Query Parameters**:
    - `status`: exp graph status(e.g:OperatorPresigned,CommitteePresigned,
      KickOff,Challenge,Assert,Take1,Take2,Disproved)
    - `operator`: operator address on chain goat
    - `from_addr`: instance from address
    - `graph_field`:peg_in tx hash or graph_id string
    - `offset`: Pagination offset
    - `limit`: Number of graphs to return
- **Response**:
  ```json
  {
    "graphs": [
        {
            "graph": {
                "graph_id": "string",
                "instance_id": "string",
                "bridge_path": "number",
                "network": "string",
                "from_addr": "string",
                "to_addr": "string",
                "amount": "number",
                "pegin_txid": "string",
                "status": "string",
                "kickoff_txid": "string",
                "challenge_txid": "string",
                "take1_txid": "number",
                "assert_init_txid": "number",
                "assert_commit_txids": "number",
                "assert_final_txid": "string",
                "take2_txid": "string",
                "disprove_txid": "string",
                "init_withdraw_txid": "string",
                "operator": "string",
                "updated_at": "number",
                "created_at": "number"
            },
             "confirmations": "number",
             "target_confirmations": "number"
        }
    ],
    "total": "number"
  }
  ```

#### Graph Presign

- **Endpoint**: `POST /v1/graphs/{id}/presign`
- **Description**: Presign a graph
- **Path Parameters**:
    - `id`: Graph ID
- **Request Body**:
  ```json
  {
    "instance_id": "string",
    "graph_ipfs_base_url": "string"
  }
  ```
- **Response**:
  ```json
  {
    "instance_id": "string",
    "graph_id": "string",
    "graph_ipfs_committee_txns": ["string"]
  }
  ```

#### Graph Presign Check

- **Endpoint**: `GET /v1/graphs/presign_check`
- **Description**: Check the presign status of a graph
- **Request Body**:
  ```json
  {
    "instance_id": "string"
  }
  ```
- **Response**:

```json
 {
  "instance_id": "string",
  "instance_status": "string",
  "graph_status": {
    "string": "string"
  },
  "tx": {
    "instance_id": "string",
    "network": "string",
    "bridge_path": "number",
    "from_addr": "string",
    "to_addr": "string",
    "amount": "number",
    "status": "string",
    "goat_txid": "string",
    "btc_txid": "string",
    "pegin_txid": null,
    "input_uxtos": "json",
    "fee": "number",
    "created_at": "number",
    "updated_at": "number"
  }
} 
```

`ps:graph_status is map<graph_id>graph_status` ,The number of `graph_status` should correspond to the number of graphs
for the given instance.
If a graph for the instance is created, the count must be greater than or equal to 1.

#### Graph TXN

- **Endpoint**: `GET /v1/graphs/{id}/txn`
- **Description**: get graph txn: kickoff take1 and so on.
- **Path Parameters**:
    - `id`: Graph ID
- **Response**:

```json
{
  "assert-commit0": "string",
  "assert-commit1": "string",
  "assert-commit2": "string",
  "assert-commit3": "string",
  "assert-init": "string",
  "assert-final": "string",
  "challenge": "string",
  "disprove": "string",
  "kickoff": "string",
  "pegin": "string",
  "take1": "string",
  "take2": "string"
}
```

- **Endpoint**: `GET /v1/graphs/{id}/tx`
- **Description**: get graph txn: kickoff take1 and so on.
- **Path Parameters**:
    - `id`: Graph ID
- **Query Parameters**:
    - `tx_name`: exp assert-commit0.hex..
    - `operator`: operator
- **Response**:

```json
{
  "tx_hex": "string"
}
```

### 5. Proofs Management

- **Endpoint**: `GET /v1/proofs/`
- **Description**: Retrieve goat block proofs, contains: block proof,aggregation proof, groth16 proof
    - **Query Parameters**:
        - `block_number`: the goat block height
        - `block_range`: the number block proofs need to query
        - `graph_id`: graph for locating Layer 2 block height
        - **Response**:
          ```json
          {
            "block_number": "number",
            "block_proofs": [
                {
                    "block_number": "number",
                    "proof_state": "string",
                    "pure_proof_cast": "number",
                    "started_at": "number",
                    "ended_at": "number"
                }
            ],
            "aggregation_proofs": [
                {
                    "block_number": "number",
                    "proof_state": "string",
                    "pure_proof_cast": "number",
                    "started_at": "number",
                    "ended_at": "number"
                }
            ],
            "groth16_proofs": [
                {
                    "block_number": "number",
                    "proof_state": "string",
                    "pure_proof_cast": "number",
                    "started_at": "number",
                    "ended_at": "number"
                }
            ]
          }
    
          ```
  PS: `proof_state` proof task state value: `queued`, `proved`, `failed`;
  `pure_proof_cast` pure compute proof cast, exclude init prepare, waiting and other time cast;
  `started_at` timestamp, proof task stared at;
  `ended_at` timestamp, proof task end at.

## Error Handling

All endpoints return appropriate HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server-side error

## Testing

The API includes comprehensive test cases for all endpoints. Tests can be run using:

```bash
cargo test rpc_service::tests 
```

## Notes

- All timestamps are in Unix timestamp format (seconds)
- Amounts are specified in satoshis
- Network types can be "mainnet" or "testnet3"
- Bridge paths are represented as numbers (1 for pBTC <-> tBTC, 2 for BTC) 
