#!/usr/bin/env bash
# Ставит бинарник rkn-guard из релиза GitHub (с проверкой sha256) и запускает rkn-guard install.
#
#   curl -fsSL https://raw.githubusercontent.com/kwlnd/rkn-guard/master/install.sh | sudo bash
#   ... | sudo bash -s -- install --no-schedule     аргументы уходят в rkn-guard install
#   ... | sudo bash -s -- binary-only               только бинарник
#
# RKN_GUARD_VERSION=v3.0.0 — конкретный релиз вместо последнего.
set -euo pipefail

REPO="${RKN_GUARD_REPO:-kwlnd/rkn-guard}"
VERSION="${RKN_GUARD_VERSION:-latest}"
BIN=/usr/local/bin/rkn-guard

die() { printf '\033[31mошибка:\033[0m %s\n' "$*" >&2; exit 1; }

# Старое баш-меню жило в /opt/rkn-guard-manager.sh, и его таймер вызывает этот
# файл с аргументами вроде update. После установки нового бинарника просто передаём их ему.
if [[ "${BASH_SOURCE[0]:-}" == /opt/rkn-guard-manager.sh && -x "$BIN" ]]; then
    exec "$BIN" "$@"
fi

[[ $EUID -eq 0 ]] || die "нужен root: curl -fsSL … | sudo bash"
[[ "$(uname -s)" == Linux ]] || die "поддерживается только Linux"
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv6l) arch=arm ;;
    i386|i686) arch=386 ;;
    *) die "архитектура $(uname -m) не поддерживается" ;;
esac
command -v sha256sum >/dev/null || die "нужен sha256sum (coreutils)"

fetch() {
    if command -v curl >/dev/null; then
        curl -fsSL --retry 2 --connect-timeout 10 -o "$2" "$1"
    elif command -v wget >/dev/null; then
        wget -q --tries=2 --timeout=10 -O "$2" "$1"
    else
        die "нужен curl или wget"
    fi
}

if [[ "$VERSION" == latest ]]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi
asset="rkn-guard-linux-$arch"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'Скачиваю %s (%s)…\n' "$asset" "$VERSION"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "не удалось скачать checksums.txt из $base"
fetch "$base/$asset" "$tmp/$asset" || die "не удалось скачать $asset из $base"
expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[[ -n "$expected" ]] || die "в checksums.txt нет $asset"
actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
[[ "$actual" == "$expected" ]] || die "sha256 не совпал: ожидался $expected, получен $actual"

install -m 755 "$tmp/$asset" "$BIN.new"
"$BIN.new" version >/dev/null || { rm -f "$BIN.new"; die "скачанный бинарник не запускается"; }
mv -f "$BIN.new" "$BIN"
printf 'Установлен %s\n' "$("$BIN" version)"

case "${1:-install}" in
    binary-only) exit 0 ;;
    install) shift || true; exec "$BIN" install "$@" ;;
    *) exec "$BIN" "$@" ;;
esac
