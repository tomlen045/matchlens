#!/usr/bin/env bash
# Verify real OpenSSH Match-block override semantics with the actual sshd binary.
set -u
TMP=$(mktemp -d /tmp/matchlens-sshd-verify.XXXXXX)
ssh-keygen -t ed25519 -N '' -q -f "$TMP/hostkey" 2>/dev/null

cat > "$TMP/sshd_test.conf" <<EOF
Port 22229
HostKey $TMP/hostkey
PidFile $TMP/sshd.pid
PasswordAuthentication no
Match User alice
    PasswordAuthentication yes
Match User bob
    PasswordAuthentication no
    PermitTTY no
EOF

echo "--- global (user=carol) ---"
/usr/sbin/sshd -T -f "$TMP/sshd_test.conf" -C user=carol,host=x,addr=127.0.0.1 2>&1 | grep -iE '^(passwordauthentication|permittty)'
echo "--- alice (block says yes) ---"
/usr/sbin/sshd -T -f "$TMP/sshd_test.conf" -C user=alice,host=x,addr=127.0.0.1 2>&1 | grep -iE '^(passwordauthentication|permittty)'
echo "--- bob (block says no+noTTY) ---"
/usr/sbin/sshd -T -f "$TMP/sshd_test.conf" -C user=bob,host=x,addr=127.0.0.1 2>&1 | grep -iE '^(passwordauthentication|permittty)'
echo "--- include test ---"
cat > "$TMP/inc.conf" <<EOF
PasswordAuthentication no
EOF
cat > "$TMP/main.conf" <<EOF
Include $TMP/inc.conf
Match User alice
    PasswordAuthentication yes
EOF
/usr/sbin/sshd -T -f "$TMP/main.conf" -C user=alice,host=x,addr=127.0.0.1 2>&1 | grep -i '^passwordauthentication'
rm -rf "$TMP"
