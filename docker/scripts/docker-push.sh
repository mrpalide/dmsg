#!/usr/bin/env bash

function print_usage() {
  echo "Use: $0 [-t <docker_image_tag_name>] [-p | -b]"
  echo "use -p for push (it builds and push the image)"
  echo "use -b for build image locally"
}

function docker_login() {
  docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD"
}

function docker_build() {
  docker image build \
    --tag=mrpalide/dmsg-server:"$tag" \
    -f ./docker/images/dmsg-server/Dockerfile .

  docker image build \
    --tag=mrpalide/dmsg-discovery:"$tag" \
    -f ./docker/images/dmsg-discovery/Dockerfile .
}

function docker_push() {
  docker tag mrpalide/dmsg-server:"$tag" mrpalide/dmsg-server:"$tag"
  docker tag mrpalide/dmsg-discovery:"$tag" mrpalide/dmsg-discovery:"$tag"
  docker image push mrpalide/dmsg-server:"$tag"
  docker image push mrpalide/dmsg-discovery:"$tag"
}

while getopts ":t:pb" o; do
  case "${o}" in
  t)
    tag="$(echo "${OPTARG}" | tr -d '[:space:]')"
    if [[ $tag == "develop" ]]; then
      tag="test"
    elif [[ $tag == "master" ]]; then
      tag="prod"
    fi
    ;;
  p)
		docker_login
    docker_build
    docker_push
    ;;
  b)
		docker_login
    docker_build
    ;;
  *)
    print_usage
    ;;
  esac
done
