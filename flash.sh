#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

FEATURES="ctap1,config-command,ed25519,ed448,es384,es512,es256k,mldsa,pq-composite,rs256,fndsa,no-reset-restrictions,debug"

usage() {
  echo "Usage: $0 [options] <target>"
  echo ""
  echo "Options:"
  echo "  --features=<features>  Comma-separated list of features to enable (default: $FEATURES)"
  echo "  --update               Update instead of flashing (preserves storage)"
  echo ""
  echo "Targets:"
  echo "  host               Simulated device on host"
  echo "  opentitan          OpenTitan board"
  echo "  nrf52840dk         Nordic nRF52840 Development Kit"
  echo "  nrf52840_dongle    Nordic nRF52840 Dongle"
  echo "  nrf52840_mdk       Makerdiary nRF52840 MDK USB Dongle"
  exit 1
}

CMD=(flash)

while [[ $# -gt 0 ]]; do
  case $1 in
    --features=*)
      FEATURES="${1#*=}"
      shift
      ;;
    --update)
      CMD=(update --both)
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      if [ -z "$TARGET" ]; then
        TARGET=$1
        shift
      else
        echo "Error: Unknown argument $1"
        usage
      fi
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "Error: Target is required."
  usage
fi

# Ensure we are in the root directory of OpenSK
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

WASEFIRE_DIR="third_party/wasefire"

if [ ! -d "$WASEFIRE_DIR" ] || [ -z "$(ls -A "$WASEFIRE_DIR")" ]; then
  echo "$WASEFIRE_DIR is empty or does not exist. Run './setup.sh' first."
  exit 1
fi

cd "$WASEFIRE_DIR"

echo "Flashing target: $TARGET"
echo "With features: $FEATURES"

SOFTWARE_CRYPTO_FEATURES="software-crypto-aes256-cbc"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-hmac-sha256"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-p256-ecdh"
SOFTWARE_CRYPTO_FEATURES+=",software-crypto-p256-ecdsa"
if [[ ",$FEATURES," == *",ed25519,"* ]]; then
  SOFTWARE_CRYPTO_FEATURES+=",software-crypto-ed25519"
fi

XTASK_FLAGS=(--release --native)
RUNNER_LOG_FLAGS=(--single-sided)
if [[ ",$FEATURES," == *",debug,"* ]]; then
  export WASEFIRE_DEBUG=1
  XTASK_FLAGS=(--native)
  RUNNER_LOG_FLAGS+=(--log=info)
fi

if [[ "$TARGET" != "host" ]]; then
  touch /tmp/opensk_flashing.lock
  trap 'rm -f /tmp/opensk_flashing.lock' EXIT
  pkill -f "probe-rs attach" 2>/dev/null || true
  sleep 1
fi

case $TARGET in
  host)
    if [ "${CMD[0]}" = "update" ]; then
      cargo xtask --native applet rust ../.. --features="$FEATURES" \
        runner host "${CMD[@]}"
    else
      cargo xtask --native applet rust ../.. --features="$FEATURES" \
        runner host flash --usb-ctap --interface=web
    fi
    ;;
  opentitan)
    cargo xtask "${XTASK_FLAGS[@]}" applet rust ../.. --opt-level=z --features="$FEATURES" \
      runner opentitan "${RUNNER_LOG_FLAGS[@]}" --opt-level=z --features=usb-ctap \
      "${CMD[@]}"
    ;;
  nrf52840dk)
    if [ "${CMD[0]}" = "flash" ]; then
      cargo xtask "${XTASK_FLAGS[@]}" applet rust ../.. --opt-level=z --features="$FEATURES" \
        runner nordic "${RUNNER_LOG_FLAGS[@]}" --opt-level=z --features=usb-ctap \
          --features="$SOFTWARE_CRYPTO_FEATURES"
      cargo build --manifest-path crates/runner-nordic/crates/bootloader/Cargo.toml \
        --release --target=thumbv7em-none-eabi --features=board-devkit,single-sided \
        -Zbuild-std=core --config='profile.release.panic="immediate-abort"'
      ./scripts/wrapper.sh probe-rs erase --chip=nRF52840_xxAA --allow-erase-all
      ./scripts/wrapper.sh probe-rs download --chip=nRF52840_xxAA target/thumbv7em-none-eabi/release/bootloader
      ./scripts/wrapper.sh probe-rs download --chip=nRF52840_xxAA target/thumbv7em-none-eabi/release/runner-nordic
      ./scripts/wrapper.sh probe-rs reset --chip=nRF52840_xxAA
    else
      cargo xtask "${XTASK_FLAGS[@]}" applet rust ../.. --opt-level=z --features="$FEATURES" \
        runner nordic "${RUNNER_LOG_FLAGS[@]}" --opt-level=z --features=usb-ctap \
          --features="$SOFTWARE_CRYPTO_FEATURES" \
        "${CMD[@]}"
    fi
    ;;
  nrf52840_dongle)
    cargo xtask "${XTASK_FLAGS[@]}" applet rust ../.. --opt-level=z --features="$FEATURES" \
      runner nordic --board=dongle "${RUNNER_LOG_FLAGS[@]}" --opt-level=z --features=usb-ctap \
        --features="$SOFTWARE_CRYPTO_FEATURES" \
      "${CMD[@]}"
    ;;
  nrf52840_mdk)
    # Ensure led-1 is included for MDK
    MDK_FEATURES="$FEATURES"
    if [[ ! "$MDK_FEATURES" =~ "led-1" ]]; then
      MDK_FEATURES="$MDK_FEATURES,led-1"
    fi
    cargo xtask --release --native applet rust ../.. --opt-level=z --features="$MDK_FEATURES" \
      runner nordic --board=makerdiary --opt-level=z --features=usb-ctap \
        --features="$SOFTWARE_CRYPTO_FEATURES" \
      "${CMD[@]}"
    ;;
  *)
    echo "Error: Unknown target $TARGET"
    usage
    ;;
esac
