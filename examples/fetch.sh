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
ARCHIVE=https://raw.githubusercontent.com/sajjadium/ctf-archives/f3d215f6627d08df2734aba7821a73c4199f106a/ctfs

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
fetch bcactf_flag_checker/whatisflag "$ARCHIVE/BCACTF/2022/rev/My_Very_Flag_Checker/whatisflag" \
    b51b1c57c958361064d2317a166fa310c1f171506d7827c4987809b53ce4ed93
fetch imaginaryctf_stings/stings "$ARCHIVE/ImaginaryCTF/2021/rev/Stings/stings" \
    e38254fe75fa2c37221c514e48ee582db9888db78386c756beb22a2710c1c60d
fetch uiuctf_tedious/challenge "$ARCHIVE/UIUCTF/2021/rev/Tedious/challenge" \
    5f600b3f841361e390cdc59c43c9c6843128ded7c366dab9a072dc039aff781b
fetch buckeyectf_angry/angry "$ARCHIVE/BuckeyeCTF/2022/rev/angry/angry" \
    f7cc87b3840efb96552ec29eb0943df3d1479097ddd6af8851a8b896896dd033
fetch imaginaryctf_keycode/key "$ARCHIVE/ImaginaryCTF/2021/rev/Keycode/key" \
    9277c66bcbce3bb8ac05aaeeb28aa00666fc00daf0665513081c1aef4bab47e3
fetch lactf_ctfd_plus/ctfd_plus "$ARCHIVE/LA/2023/rev/ctfd-plus/ctfd_plus" \
    3f350e359283b21c0c7d8a1cdbdb978f840534d393740a2dd009b8cb02e95f2c
fetch lactf_patricks_paraflag/patricks-paraflag \
    "$ARCHIVE/LA/2025/rev/patricks_paraflag/patricks-paraflag" \
    05b449309cc237871116bcb53346db413e902ddec7515eaad904ac0c45726f1d
fetch knightctf_flag_vault/The_Flag_Vault "$ARCHIVE/KnightCTF/2022/rev/The_Flag_Vault/The_Flag_Vault" \
    87e9b7203adc6a23059cec62fcdaee6e10d36f1d941caa9be88b5cc55ae5747e
fetch imaginaryctf_unoriginal/unoriginal "$ARCHIVE/ImaginaryCTF/2024/rev/unoriginal/unoriginal" \
    b0bce1d9ca56991fb899b4fb5450c52ad245a71aab0e34c56d81be0e48186a02
fetch byuctf_reveng/gettingBetter "$ARCHIVE/BYUCTF/2023/rev/RevEng/gettingBetter" \
    d58ded97ee82ebf47aaa314cc2615b4a0f96966ccea715bda937b6a04f76a114
fetch lactf_shattered_memories/shattered-memories \
    "$ARCHIVE/LA/2024/rev/shattered_memories/shattered-memories" \
    36e6c56f34a05b87591a1ba3e622f9fecf4412616ce4cfb834b7d6d2394ef828
fetch hsctf_keygen/keygen "$ARCHIVE/HSCTF/2023/rev/keygen/keygen" \
    d1f4fd3e4a0935e25ef630ca70bd74d54372b84b9a86d214d731f7979b2bce9a
fetch lactf_string_cheese/string_cheese "$ARCHIVE/LA/2023/rev/string-cheese/string_cheese" \
    eba17b9931d826b8573291ab25833a4a6394f110dbd3b6c95e67bc2df606e1c9
fetch ductf_no_strings/nostrings "$ARCHIVE/DownUnderCTF/2021/rev/no_strings/nostrings" \
    62bdc1ff08af6647109112372fdcb09a9f3eaa0d164a8542e251de9ecbdb187f
