echo "Bash Implemetation of ADB restart. Kills, and Restarts server."

echo "[*] Killing ADB server"
adb kill-server

echo "[*] Starting ADB server"
adb start-server

