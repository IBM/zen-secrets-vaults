#!/bin/sh

GIT_COMMIT_ID=$(git rev-parse --short HEAD)
GIT_REMOTE_URL=$(git config --get remote.origin.url)
IMAGE_BUILD_OPTS="--build-arg VCS_REF=${GIT_COMMIT_ID} --build-arg VCS_URL=${GIT_REMOTE_URL}"

set -e
set -x

export ARCH=`uname -m`
install_required_tools()
{
        if ! [ -x "$(command -v pip)" ]
        then
          echo "python and python-pip are required. Please install them"
          exit 1
        else
          python3 -m pip install --user virtualenv
          rm -rf venv
          python3 -m venv env
          source env/bin/activate
          pip install jinja2-cli
        fi
}

generate_files_from_template()
{
        echo "generating files for $ARCH architecture"
        project_path=$1
        path_to_list=${project_path}/templates_list.txt

        if [ -f ${path_to_list} ]
        then
          # Install jinja2-cli package if not present on the machine as the template script requires jinja2-cli
          # to be present.
          install_required_tools
          while read template_file
          do
            generate_file_from_template  ${project_path}/${template_file} ${project_path}
          done < ${path_to_list}
        else
          echo "templates_list.txt file is not found in ${project_path}"
        fi
}

generate_file_from_template()
{
         path_to_template=$1
         path_to_data=$2

         if [ -f ${path_to_template} ]
         then
          jinja2 ${path_to_template} ${path_to_data}/data_$ARCH.json > ${path_to_template%.j2}
          echo "${path_to_template%.j2} was generated for $ARCH architecture"
        else
          echo "${path_to_template} is not found"
        fi
}

scriptdir=`dirname ${0}`
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