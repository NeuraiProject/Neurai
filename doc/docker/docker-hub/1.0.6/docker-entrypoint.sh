#!/bin/sh
set -eu

data_dir=/data
config_file="${data_dir}/neurai.conf"

if [ ! -f "${config_file}" ]; then
    umask 077
    cat > "${config_file}" <<EOF
# Created on the first start of this container. This file is persisted in /data.
listen=${NEURAI_LISTEN:-1}
server=1
port=${NEURAI_P2P_PORT:-19000}
rpcport=${NEURAI_RPC_PORT:-19001}
rpcbind=${NEURAI_RPC_BIND:-127.0.0.1}
rpcallowip=${NEURAI_RPC_ALLOW_IP:-127.0.0.1}
rpcthreads=${NEURAI_RPC_THREADS:-4}
rpcworkqueue=${NEURAI_RPC_WORK_QUEUE:-16}
rest=${NEURAI_REST:-0}
disablewallet=${NEURAI_DISABLE_WALLET:-0}
walletbroadcast=${NEURAI_WALLET_BROADCAST:-1}
walletrbf=${NEURAI_WALLET_RBF:-0}
txindex=${NEURAI_TXINDEX:-0}
assetindex=${NEURAI_ASSETINDEX:-0}
addressindex=${NEURAI_ADDRESSINDEX:-0}
timestampindex=${NEURAI_TIMESTAMPINDEX:-0}
spentindex=${NEURAI_SPENTINDEX:-0}
maxconnections=${NEURAI_MAX_CONNECTIONS:-125}
prune=${NEURAI_PRUNE:-0}
dbcache=${NEURAI_DB_CACHE:-450}
par=${NEURAI_SCRIPT_THREADS:-0}
maxmempool=${NEURAI_MAX_MEMPOOL:-300}
persistmempool=${NEURAI_PERSIST_MEMPOOL:-1}
EOF

    if [ -n "${NEURAI_WALLET_FILE:-}" ]; then
        printf 'wallet=%s\n' "${NEURAI_WALLET_FILE}" >> "${config_file}"
    fi

    if [ -n "${NEURAI_RPC_USER:-}" ] || [ -n "${NEURAI_RPC_PASSWORD:-}" ]; then
        if [ -z "${NEURAI_RPC_USER:-}" ] || [ -z "${NEURAI_RPC_PASSWORD:-}" ]; then
            echo "NEURAI_RPC_USER and NEURAI_RPC_PASSWORD must be set together" >&2
            exit 1
        fi
        printf 'rpcuser=%s\nrpcpassword=%s\n' \
            "${NEURAI_RPC_USER}" "${NEURAI_RPC_PASSWORD}" >> "${config_file}"
    fi

    # ZMQ is disabled unless an endpoint is explicitly configured. A TCP endpoint
    # should normally bind to 0.0.0.0 inside a trusted Docker network.
    for notifier in \
        "zmqpubhashblock:${NEURAI_ZMQ_PUB_HASH_BLOCK:-}" \
        "zmqpubhashtx:${NEURAI_ZMQ_PUB_HASH_TX:-}" \
        "zmqpubrawblock:${NEURAI_ZMQ_PUB_RAW_BLOCK:-}" \
        "zmqpubrawtx:${NEURAI_ZMQ_PUB_RAW_TX:-}" \
        "zmqpubrawmessage:${NEURAI_ZMQ_PUB_RAW_MESSAGE:-}"; do
        option=${notifier%%:*}
        endpoint=${notifier#*:}
        if [ -n "${endpoint}" ]; then
            printf '%s=%s\n' "${option}" "${endpoint}" >> "${config_file}"
        fi
    done

    if [ -n "${NEURAI_EXTRA_CONF:-}" ]; then
        printf '\n# Additional configuration supplied at first start\n%s\n' \
            "${NEURAI_EXTRA_CONF}" >> "${config_file}"
    fi

    chown neurai:neurai "${config_file}"
fi

exec gosu neurai neuraid -datadir="${data_dir}" "$@"
