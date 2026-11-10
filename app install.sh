#!/usr/bin/env bash
# Оставлен для старого баш-меню: его пункт «Обновить» скачивает этот файл,
# чтобы заменить бинарник. Теперь всё делает install.sh.
set -euo pipefail
url="https://raw.githubusercontent.com/${RKN_GUARD_REPO:-kwlnd/rkn-guard}/master/install.sh"
script=$(mktemp)
trap 'rm -f "$script"' EXIT
if command -v curl >/dev/null; then curl -fsSL "$url" -o "$script"; else wget -qO "$script" "$url"; fi
bash "$script" binary-only
