#!/usr/bin/env bash
# Download the original challenge binaries into examples/<name>/.
#
# They are other people's CTF challenges, so this repository does not include them: each
# one is fetched from a public archive at a pinned commit and checked against its SHA-256.
# Nothing downloaded is executed.
set -euo pipefail
cd "$(dirname "$0")"

ANGR_DOC=https://raw.githubusercontent.com/angr/angr-doc/bf380700f2baa092c2970a2dceb0eb2793bd9837/examples
BELEAF=https://raw.githubusercontent.com/KevOrr/ctf-writeups/a94bd1c21e1f483b20ff16fefd7eda2ae581eada/2019/csaw/rev/beleaf
PICO_2022=https://raw.githubusercontent.com/HHousen/PicoCTF-2022/60afc827a7763b238d4990916dff1df49fbcad07/Reverse%20Engineering

fetch() {
    local target=$1 url=$2 digest=$3
    if [[ -f $target ]] && echo "$digest  $target" | sha256sum --check --status; then
        echo "have    $target"
        return
    fi
    mkdir -p "$(dirname "$target")"
    curl --fail --silent --show-error --location --max-time 60 --output "$target.part" "$url"
    if ! echo "$digest  $target.part" | sha256sum --check --status; then
        rm -f "$target.part"
        echo "checksum mismatch: $url" >&2
        exit 1
    fi
    mv "$target.part" "$target"
    echo "fetched $target"
}

fetch ais3_crackme/ais3_crackme "$ANGR_DOC/ais3_crackme/ais3_crackme" \
    12b99604d85d44adde22ed566e3a01cd474c4ce6f3e271f087162e7feb11d454
fetch defcamp_r100/r100 "$ANGR_DOC/defcamp_r100/r100" \
    8c481c589e9f95acbfdc20b54f5965017604a4c149dd72ec6bde55a5ea2a11bc
fetch google_unbreakable/unbreakable-enterprise-product-activation \
    "$ANGR_DOC/google2016_unbreakable_0/unbreakable-enterprise-product-activation" \
    24be61692a69f8321a3766e2abe7da53630ea82a407718b268d95b22d4790784
fetch csaw_beleaf/beleaf "$BELEAF/beleaf" \
    443d56b403ef0d859b9862758b4911403ba606e5f4c9c048f4ef99722de0c68b
fetch picoctf_bbbbloat/bbbbloat "$PICO_2022/Bbbbloat/bbbbloat" \
    6676a9c9e4eb5870c7312e21c403f5ea7b34c9ed510d161e049d26fcde3f705d
