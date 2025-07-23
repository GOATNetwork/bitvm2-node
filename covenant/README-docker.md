# Build Docker Images

```
# Optional: install ziren rust toolchain
# curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/ProjectZKM/toolchain/refs/heads/main/setup.sh | sh

sh docker.sh build
```

# Push Docker Images to the GitHub

```
# Optional
# echo "${GIT_TOKEN}" | docker login ghcr.io -u ${GIT_USER} --password-stdin

export GIT_USER=

sh docker.sh push
```

# Start Proof Services

```
export GIT_USER=
export DB_DIR=
export CHAIN_ID=

# block number for the continuous service
export C_BLOCK_NUMBER=

# block number for the aggregation service
export A_BLOCK_NUMBER=

docker-compose up -d

# docker-compose start continuous

# docker-compose start aggregation
```

# Stop Proof Services

```
docker-compose down

# docker-compose stop continuous

# docker-compose stop aggregation
```

# View logs

```
tail -f logs/continuous.log.2025-07-23

tail -f logs/aggregation.log.2025-07-23 
```
