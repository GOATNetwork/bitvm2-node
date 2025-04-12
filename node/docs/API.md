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
    "actor": "string"
  }
  ```
- **Response**:

```json
{
  "peer_id": "string",
  "actor": "string",
  "update_at": "string"
}
```

#### Get Nodes

- **Endpoint**: `GET /v1/nodes`
- **Description**: Retrieve a list of nodes with optional filtering
- **Query Parameters**:
    - `role`: Filter nodes by role (e.g., "OPERATOR")
    - `offset`: Pagination offset
    - `limit`: Number of nodes to return
- **Response**:

```json
{
  "nodes": [
    {
      "peer_id": "string",
      "actor": "string",
      "updated_at": "string",
      "status": "string"
    }
  ]
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
    "instance_id": "string",
    "bridge_path": "string",
    "from_addr": "string",
    "to_addr": "string",
    "amount": "number",
    "created_at": "number",
    "update_at": "number",
    "status": "string",
    "goat_txid": "string",
    "btc_txid": "string",
    "pegin_tx": "string",
    "kickoff_tx": "string"
}
```

#### Filter Instances

- **Endpoint**: `GET /v1/instances`
- **Description**: Retrieve a list of instances with optional filtering
- **Query Parameters**:
    - `user_address`: Filter by user address
    - `offset`: Pagination offset
    - `limit`: Number of instances to return
- **Response**: List of instances matching the criteria

```json
{
  "instances": [
    {
      "instance_id": "string",
      "status": "string",
      "created_at": "number"
    }
  ]
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
    - `offset`: Pagination offset
    - `limit`: Number of graphs to return
- **Response**:
  ```json
  {
  "graphs": [{
    "graph_id": "string",
    "instance_id": "string",
    "graph_ipfs_base_url": "string",
    "peg_in_txid": "string",
    "amount": "number",
    "created_at": "number",
    "status": "string",
    "challenge_txid": "string",
    "disprove_txid": "number"
  }]
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
    "graph_ipfs_committee_txns": "string"
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
    "graph_status": "json",
    "tx":{
    "instance_id": "string",
    "bridge_path": "string",
    "from_addr": "string",
    "to_addr": "string",
    "amount": "number",
    "created_at": "number",
    "update_at": "number",
    "status": "string",
    "goat_txid": "string",
    "btc_txid": "string",
    "pegin_tx": "string",
    "kickoff_tx": "string"
  } 
  }
  ```
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