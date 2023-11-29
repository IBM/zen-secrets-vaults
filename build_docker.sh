#!/bin/sh

GIT_COMMIT_ID=$(git rev-parse --short HEAD)
GIT_REMOTE_URL=$(git config --get remote.origin.url)
IMAGE_BUILD_OPTS="--build-arg VCS_REF=${GIT_COMMIT_ID} --build-arg VCS_URL=${GIT_REMOTE_URL}"

set -e
set -x

scriptdir=`dirname ${0}`
. ${scriptdir}/../devtest-helpers/utils/common.sh

cd ${scriptdir}
fullpath=$(pwd)
dockerfiledir=${scriptdir}/build
install_required_tools
generate_file_from_template ${dockerfiledir}/Dockerfile.j2 ${dockerfiledir}

if [ "$1" != "" ]; then
  short_and_version="zen-vault-bridge:$1"
elif [ "${IMAGE_VERSION_TAG}" != "" ]; then
  short_and_version="zen-vault-bridge:${IMAGE_VERSION_TAG}"
else
  short_and_version="zen-vault-bridge"
fi

trap 'report_failure ${LINENO} $?'  ERR

echo =============================
date

arch=$(uname -m)
if [ $arch == "arm64" ]; then
  docker build --platform linux/amd64 ${IMAGE_BUILD_OPTS} --pull --no-cache -f build/Dockerfile -t localhost:5000/${short_and_version} .
else
  docker build ${IMAGE_BUILD_OPTS} --pull --no-cache -f build/Dockerfile -t localhost:5000/${short_and_version} .
fi
date