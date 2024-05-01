#!/bin/env bash

if [ -z "$2" ]; then
    >&2 echo "Error: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY environment variables is not set"
    exit 1
fi

PROJECTNAME="aws-serverless-web-app"
found=$(lxc info "$PROJECTNAME" 2>/dev/null | grep "Name: $PROJECTNAME")
if [ -n "$found" ]; then
    >&2 echo "Error: Instance $PROJECTNAME has already been created"
    exit 1
fi

PROJECTPATH="$( dirname -- "$( readlink -f -- "$0"; )"; )"
WORK_DIR=`mktemp -d --suffix=_$PROJECTNAME`
if [ ! -e "$WORK_DIR" ]; then
    >&2 echo "Error: Failed to create temp directory"
    exit 1
fi
function cleanup {      
  rm -rf "$WORK_DIR"
  echo "Deleted temp working directory $WORK_DIR"
}
trap cleanup EXIT

lxc launch ubuntu:noble $PROJECTNAME < $PROJECTPATH/lxd-instance.yaml

mkdir $WORK_DIR/.aws
chmod 755 $WORK_DIR/.aws

touch $WORK_DIR/.aws/credentials
chmod 600 $WORK_DIR/.aws/credentials
cat <<EOF >  $WORK_DIR/.aws/credentials
[default]
aws_access_key_id = $1
aws_secret_access_key = $2

EOF

touch $WORK_DIR/.aws/config
chmod 600 $WORK_DIR/.aws/config
cat <<EOF >  $WORK_DIR/.aws/config
[default]
region = eu-central-1
output = json

EOF

lxc exec $PROJECTNAME -- cloud-init status --wait
lxc file push -r $WORK_DIR/.aws $PROJECTNAME/root/
lxc exec $PROJECTNAME -- aws --version
