# Container image that runs your code
FROM ubuntu:latest

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY entrypoint.sh /entrypoint.sh
COPY target/release/bitvm2-noded /usr/local/bin

RUN apt update && apt install sqlite3 ca-certificates -y && update-ca-certificates

# should map your .env to /app/.env
WORKDIR /app

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
