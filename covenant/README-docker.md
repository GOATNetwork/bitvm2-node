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
# DB directory in host.
export DB_DIR=

BLOCK_NUMBER_C=1 docker-compose up -d continuous

BLOCK_NUMBER_A=2 docker-compose up -d aggregation

# BLOCK_NUMBER_C=1 BLOCK_NUMBER_A=2 docker-compose up -d
```

# Stop Proof Services

```
docker-compose down continuous

docker-compose down aggregation

# docker-compose down
```

# View logs

```
tail -f logs/continuous.log.2025-07-23

tail -f logs/aggregation.log.2025-07-23 
```
