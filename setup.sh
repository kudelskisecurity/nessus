#!/bin/sh

set -eux

tail /tmp/compose_log
cat /tmp/compose_log
awk "/^NESSUS_[A-Z]+_KEY='[a-z0-9]+'$/ {print \"export \" \$0}" /tmp/compose_log > /tmp/keys
cat /tmp/keys
