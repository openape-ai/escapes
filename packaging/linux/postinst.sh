#!/bin/bash
set -e

if [ ! -f /etc/openape/config.toml ]; then
    cp /usr/local/share/openape/config.example.toml /etc/openape/config.toml
    chmod 0644 /etc/openape/config.toml
    echo ""
    echo "==> Edit /etc/openape/config.toml before use."
    echo "    Required: [security] allowed_issuers and allowed_approvers"
    echo ""
fi
