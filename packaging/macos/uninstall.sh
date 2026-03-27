#!/bin/bash
set -e

echo "Uninstalling OpenApe Escapes..."

sudo rm -f /usr/local/bin/escapes
sudo rm -rf /usr/local/share/openape

printf "Remove config (/etc/openape)? [y/N] "
read -r answer
if [ "$answer" = "y" ]; then
    sudo rm -rf /etc/openape
fi

printf "Remove audit logs (/var/log/openape)? [y/N] "
read -r answer
if [ "$answer" = "y" ]; then
    sudo rm -rf /var/log/openape
fi

sudo pkgutil --forget at.openape.escapes 2>/dev/null || true
echo "Done."
