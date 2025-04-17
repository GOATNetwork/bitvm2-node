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

- **Endpoint**: `POST /v1/nodes`
- **Description**: Create a new node in the network
- **Request Body**:
  ```json
  {
    "peer_id": "string",
    "actor": "string",
    "eth_addr": "string",
    "btc_pub_key": "string"
  }
  ```
- **Response**:

```json
{
  "peer_id": "string",
  "actor": "string",
  "eth_addr": "string",
  "btc_pub_key": "string",
  "updated_at": "number",
  "created_at": "number"
}
```

#### Get Nodes

- **Endpoint**: `GET /v1/nodes`
- **Description**: Retrieve a list of nodes with optional filtering
- **Query Parameters**:
    - `actor`: Filter nodes by acotr (e.g., "OPERATOR")
    - `goat_addr`: Filter nodes by goat address (e.g., "OPERATOR")
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
    "offline_committee": "number"
  }
}
```

### 2. Instance Management

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
      "pegin_tx_height": "number",
      "kickoff_tx": null,
      "input_uxtos": "json",
      "fee": "number",
      "created_at": "number",
      "updated_at": "number"
    },
    "eta": "string",
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
          "pegin_tx_height": "number",
          "kickoff_tx": null,
          "input_uxtos": "json",
          "fee": "number",
          "created_at": "number",
          "updated_at": "number"
        },
        "eta": "string",
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
- **Description**: Retrieve instance overiew
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
    "graph_id": "string",
    "instance_id": "string",
    "graph_ipfs_base_url": "string",
    "peg_in_txid": "string",
    "amount": "number",
    "created_at": "number",
    "status": "string",
    "challenge_txid": "string",
    "disprove_txid": "number"    
  }
  ```

#### Get Graphs

- **Endpoint**: `GET /v1/graphs`
- **Description**: Retrieve a list of graphs with optional filtering
- **Query Parameters**:
    - `stauts`: exp graph status(e.g:OperatorPresigned,CommitteePresigned, KickOff,Challenge,Assert,Take1,Take2,Disproved)
    - `operator`: operator address on chain goat 
    - `pegin_txid`:peg_in tx hash 
    - `offset`: Pagination offset
    - `limit`: Number of graphs to return
- **Response**:
  ```json
  {
    "graphs": [
        {
            "graph_id": "string",
            "instance_id": "string",
            "graph_ipfs_base_url": "string",
            "pegin_txid": "string",
            "amount": "number",
            "created_at": "number",
            "updated_at": "number",
            "status": "string",
            "challenge_txid": "string",
            "disprove_txid": "string",
            "operator": "string"
        }
    ],
    "total": "number"}
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
    "graph_ipfs_committee_txns": ["string"],
  }
  ```

#### Graph Presign Check

- **Endpoint**: `POST /v1/graphs/presign_check`
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
        "pegin_tx_height": "number",
        "kickoff_tx": null,
        "input_uxtos": "json",
        "fee": "number",
        "created_at": "number",
        "updated_at": "number"
    }
  } 
```
ps:graph_status is map<graph_id>graph_status

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