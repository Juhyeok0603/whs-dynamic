#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-sandbox/fixtures/home/analyzer}"
mkdir -p "$ROOT/.aws" "$ROOT/.ssh" "$ROOT/.config/pip"
printf '%s\n' '[default]' 'aws_access_key_id = AKIAFAKEANALYSISKEY' 'aws_secret_access_key = fake-analysis-secret' > "$ROOT/.aws/credentials"
printf '%s\n' 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFAKE analysis-fixture' > "$ROOT/.ssh/id_rsa"
printf '%s\n' '[global]' 'index-url = https://pypi.org/simple' > "$ROOT/.config/pip/pip.conf"
printf '%s\n' 'machine example.invalid login fake-user password fake-password' > "$ROOT/.netrc"
chmod 700 "$ROOT/.ssh" "$ROOT/.aws" "$ROOT/.config/pip"
chmod 600 "$ROOT/.ssh/id_rsa" "$ROOT/.aws/credentials" "$ROOT/.netrc"
echo "Created dummy credential fixture at $ROOT"
