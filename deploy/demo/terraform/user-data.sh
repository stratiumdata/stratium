#!/bin/sh
# First boot only: Docker from Docker's own signed repository (engine, buildx
# and the compose plugin together), plus git and make for the checkout.
# Ubuntu's unattended-upgrades is on by default and keeps applying security
# updates.
set -eu
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl git make
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
	> /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
