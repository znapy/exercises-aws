#!/bin/env bash

source .env

error=0
if [ -z "$2" ]; then
    if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        >&2 echo "Error: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY parameters is not set"
        error=1
    fi
fi
if [ -z "$PROJECTNAME" ]; then
    >&2 echo "Error: evironment variable PROJECTNAME is not set"
    error=1
fi
if [ -z "$IAM_USER" ]; then
    >&2 echo "Error: evironment variable IAM_USER is not set"
    error=1
fi
if [ -z "$IAM_USER_MAIL" ]; then
    >&2 echo "Error: evironment variable IAM_USER_MAIL is not set"
    error=1
fi
if [ -z "$REGION" ]; then
    >&2 echo "Error: evironment variable REGION is not set"
    error=1
fi
if [ $error -eq 1 ]; then
    exit 1
fi

if [ -n "$1" ]; then
    AWS_ACCESS_KEY_ID=$1
fi
if [ -n "$2" ]; then
    AWS_SECRET_ACCESS_KEY=$2
fi

found=$(lxc info "$PROJECTNAME" 2>/dev/null | grep "Name: $PROJECTNAME")
if [ -n "$found" ]; then
    >&2 echo "Error: Instance $PROJECTNAME has already been created"
    exit 1
fi

PROJECTPATH="$( dirname -- "$( readlink -f -- "$0"; )"; )/$PROJECTNAME"
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
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY

EOF

touch $WORK_DIR/.aws/config
chmod 600 $WORK_DIR/.aws/config
cat <<EOF >  $WORK_DIR/.aws/config
[default]
region = $REGION
output = json

[profile $PROJECTNAME]
region = $REGION
IAM_USER = $IAM_USER
IAM_USER_MAIL = $IAM_USER_MAIL

EOF

lxc exec $PROJECTNAME -- cloud-init status --wait
lxc file push -r $WORK_DIR/.aws $PROJECTNAME/root/
lxc exec $PROJECTNAME -- aws --version

lxc file push --recursive $PROJECTPATH $PROJECTNAME/root/
lxc exec $PROJECTNAME -- python3.12 /root/$PROJECTNAME/start.py
