#!/bin/sh

build_images() {
    cd aggregation && cargo build -r
    cd ../continuous  && cargo build -r

    cd tool && ./certgen.sh && cd ../../

    docker build -t aggregation:latest . -f ./Dockerfile.aggregation

    docker build -t continuous:latest . -f ./Dockerfile.continuous
}

push_images() {
    # echo "${GIT_TOKEN}" | docker login ghcr.io -u ${GIT_USER} --password-stdin

    docker tag aggregation:latest ghcr.io/${GIT_USER}/aggregation:latest
    docker push ghcr.io/${GIT_USER}/aggregation:latest

    docker tag continuous:latest ghcr.io/${GIT_USER}/continuous:latest   
    docker push ghcr.io/${GIT_USER}/continuous:latest
}

main() {
    cmd=$1

    if [ "$cmd" = "build" ];then
        build_images
        exit 0
    fi

    if [ "$cmd" = "push" ];then
        push_images
        exit 0
    fi
}

main $@
