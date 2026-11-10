#!/usr/bin/env bash
# Проверка на реальном ipset. Только одноразовый раннер GitHub и отдельное
# сетевое пространство имён: sudo unshare --net env ... bash этот_файл
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && $EUID == 0 ]] || exit 1
[[ $(readlink /proc/self/ns/net) != $(readlink /proc/1/ns/net) ]] || {
    echo 'Запустите проверку через unshare --net.' >&2
    exit 1
}
work=$(mktemp -d /tmp/rkn-extra-ipset.XXXXXX)
server=''
had_config=no
if [[ -e /etc/ipset.conf ]]; then
    cp -p /etc/ipset.conf "$work/original.conf"
    had_config=yes
fi
cleanup() {
    [[ -z "$server" ]] || { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }
    if [[ "$had_config" == yes ]]; then cp -p "$work/original.conf" /etc/ipset.conf; else rm -f /etc/ipset.conf; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
ip link set lo up
mkdir "$work/www" "$work/state"
# Пересекающиеся подсети должны схлопнуться: 192.0.2.0/25 + /25 → /24, /26 внутри исчезает.
printf '192.0.2.0/25\n192.0.2.128/25\n192.0.2.64/26\n2001:db8::/32\n' > "$work/www/base"
printf '192.0.2.0/24\n198.51.100.0/24\n2001:db8:1::/48\n' > "$work/www/extra"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/www" > "$work/http.log" 2>&1 &
server=$!
url=http://127.0.0.1:18080
for ((i=0; i<100; i++)); do
    if curl -fsS "$url/base" >/dev/null 2>&1; then break; fi
    sleep 0.05
done
printf '%s/base\n' "$url" > "$work/base-sources"
run() { "$RKN_TEST_BINARY" --state-dir "$work/state" --base-sources "$work/base-sources" "$@"; }
expect_status() {
    local expected=$1 actual=0
    shift
    "$@" > "$work/result.log" 2>&1 || actual=$?
    [[ "$actual" == "$expected" ]] || { cat "$work/result.log"; echo "Код $actual вместо $expected" >&2; exit 1; }
}
# «! cmd» под set -e не останавливает скрипт, поэтому отсутствие проверяем явно.
absent() { if ipset test "$1" "$2" 2>/dev/null; then echo "$2 не должен быть в $1" >&2; exit 1; fi; }
entries() { grep -c "^add $1 " /etc/ipset.conf || true; }

ipset create foreign hash:net
ipset add foreign 198.18.0.0/15
iptables -N SCANNERS-BLOCK
iptables -A SCANNERS-BLOCK -j RETURN -c 42 4096
iptables -vnxL SCANNERS-BLOCK > "$work/counters.before"

run update
[[ $(entries SCANNERS-BLOCK-V4) == 1 ]] || { cat /etc/ipset.conf; echo 'подсети не схлопнулись' >&2; exit 1; }
ipset test SCANNERS-BLOCK-V4 192.0.2.200

run sources add --disabled "$url/extra"
absent SCANNERS-BLOCK-V4 198.51.100.1
run sources enable 1
ipset test SCANNERS-BLOCK-V4 198.51.100.1
ipset test SCANNERS-BLOCK-V6 2001:db8:1::1
run sources disable 1
absent SCANNERS-BLOCK-V4 198.51.100.1
ipset test SCANNERS-BLOCK-V4 192.0.2.1
run sources enable 1

# Ручные баны: оба семейства, переживают update, снимаются без сети.
run ban 203.0.113.7 2001:db8:ffff::1
ipset test SCANNERS-BLOCK-V4 203.0.113.7
ipset test SCANNERS-BLOCK-V6 2001:db8:ffff::1
run update
ipset test SCANNERS-BLOCK-V4 203.0.113.7
kill "$server"; wait "$server" 2>/dev/null || true; server=''
run unban 203.0.113.7
absent SCANNERS-BLOCK-V4 203.0.113.7
ipset test SCANNERS-BLOCK-V6 2001:db8:ffff::1
expect_status 1 run unban 203.0.113.7
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/www" > "$work/http.log" 2>&1 &
server=$!
for ((i=0; i<100; i++)); do curl -fsS "$url/base" >/dev/null 2>&1 && break; sleep 0.05; done

# Битый источник: берётся последняя корректная копия, код 2.
printf '203.0.113.0/24\n2001:db8::/32\n' > "$work/www/base"
printf '198.51.100.9/32\nне CIDR\n' > "$work/www/extra"
expect_status 2 run update
grep -q 'последние корректные данные' "$work/result.log"
ipset test SCANNERS-BLOCK-V4 198.51.100.1
ipset test SCANNERS-BLOCK-V4 203.0.113.1
cp /etc/ipset.conf "$work/last-good.conf"
rm "$work/www/extra"
expect_status 2 run update
# У нового hash:net меняется служебный initval; сравниваем именно записи подсетей.
grep '^add ' /etc/ipset.conf | LC_ALL=C sort > "$work/current.sorted"
grep '^add ' "$work/last-good.conf" | LC_ALL=C sort > "$work/previous.sorted"
cmp "$work/current.sorted" "$work/previous.sorted"
cp /etc/ipset.conf "$work/last-good.conf"

# Сбой заливки в ipset не трогает рабочие наборы и сохранённый файл.
mkdir "$work/bin"
real_ipset=$(command -v ipset)
cat > "$work/bin/ipset" <<EOF
#!/bin/bash
if [[ "\$1" == restore ]]; then exit 77; fi
exec "$real_ipset" "\$@"
EOF
chmod 755 "$work/bin/ipset"
expect_status 1 env PATH="$work/bin:$PATH" "$RKN_TEST_BINARY" --state-dir "$work/state" --base-sources "$work/base-sources" update
cmp /etc/ipset.conf "$work/last-good.conf"
ipset test SCANNERS-BLOCK-V4 198.51.100.1
ipset test SCANNERS-BLOCK-V6 2001:db8:1::1

run sources remove 1
absent SCANNERS-BLOCK-V4 198.51.100.1
ipset test SCANNERS-BLOCK-V4 203.0.113.1
ipset test foreign 198.18.0.1
if ipset list -name | grep -q '^RKN-NEXT'; then echo 'остался временный набор' >&2; exit 1; fi
iptables -vnxL SCANNERS-BLOCK > "$work/counters.after"
cmp "$work/counters.before" "$work/counters.after"
echo 'Пройдены проверки реального ipset: схлопывание, источники, баны, кеш, ошибки, откат и счётчики.'
