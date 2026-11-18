# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
#
# Rendered by `make demo` (vhs, https://github.com/charmbracelet/vhs) from
# the repository root, after it has built examples/hash.cpp into
# build-demo/. It needs a crypto-server at CRYPTO_SERVICE_URL with
# CRYPTO_SERVICE_API_KEY in the environment (synthetic values only). On
# screen, the server's health, then the hash example computing SHA-256
# and BLAKE3 digests through the SDK. Nothing leaves loopback.
Output .github/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WaitTimeout 60s
Set WaitPattern /^\$ ?$/

Hide
Type `export PATH="$PWD/build-demo:$PATH" PS1='$ ' && clear`
Enter
Sleep 500ms
Show

Type `curl -s "$CRYPTO_SERVICE_URL/health"`
Sleep 500ms
Enter
Wait
Sleep 4s

Type "crypto_service_hash"
Sleep 500ms
Enter
Wait
Sleep 8s
