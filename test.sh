#!/usr/bin/env sh

set -eu

: ${REMOTE_NESSUS_PORT:='8834'}
: ${LOCAL_NESSUS_IP:='localhost'}
: ${LOCAL_NESSUS_PORT:='8835'}

export NESSUS_URL="https://${LOCAL_NESSUS_IP}:${LOCAL_NESSUS_PORT}"

bind_remote() {
        local remote_ip="${1}"
        local remote_port="${2}"
        local remote_user="${3}"
        local local_ip="${4}"
        local local_port="${5}"
        ssh -N -L "${local_port}:${local_ip}:${remote_port}" \
                "${remote_user}@${remote_ip}" &
        to_kill="${!} ${to_kill}"
}

bind_remote_nessus() {
        bind_remote "${REMOTE_NESSUS_IP}" "${REMOTE_NESSUS_PORT}" \
                "${REMOTE_NESSUS_USER}" "${LOCAL_NESSUS_IP}" \
                "${LOCAL_NESSUS_PORT}"
}

trap on_exit EXIT INT
to_kill=''
on_exit() {
        [ -n "${to_kill}" ] && kill ${to_kill}
}

bind_remote_nessus

python -m unittest discover
