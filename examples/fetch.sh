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

fetch_zip() {
    local target=$1 url=$2 digest=$3 member=$4
    if [[ -f $target ]]; then
        echo "have    $target"
        return
    fi
    mkdir -p "$(dirname "$target")"
    curl --fail --silent --show-error --location --max-time 60 --output "$target.zip" "$url"
    if ! echo "$digest  $target.zip" | sha256sum --check --status; then
        rm -f "$target.zip"
        echo "checksum mismatch: $url" >&2
        exit 1
    fi
    unzip -p "$target.zip" "$member" > "$target"
    rm -f "$target.zip"
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
fetch swampctf_beginner_rev/BeginnerREV "$ARCHIVE/SwampCTF/2024/rev/Beginner_Rev/BeginnerREV" \
    97954541938d204f912fee00607c52d910e6eb6d04fd7bee94cd503fd9478ca1
fetch tamuctf_nope/nope "$ARCHIVE/TAMUctf/2023/rev/nope/nope" \
    51555767fbc46b57f4e60f2daaefc9ade60d959af41fd2cf35bab75584aaa266
fetch b01lers_crackme/crackme "$ARCHIVE/b01lers/2022/rev/crackme/crackme" \
    803297bd98b1611303e70403aee8b0d4c13213dfc8f8975b94e7a333007cc538
fetch b01lers_crackme_2/crackme_2 "$ARCHIVE/b01lers/2022/rev/crackme_2/crackme_2" \
    34ba696bbe1ed17088182be50c5692853a6eb8322578db7f10d47c42704191b7
fetch angstrom_one_bite/one_bite "$ARCHIVE/angstromCTF/2019/rev/One_Bite/one_bite" \
    697526f731d6484c6fc1066070b722e3a833bef6c3280fcbae1004083460e887
fetch angstrom_high_quality_checks/high_quality_checks \
    "$ARCHIVE/angstromCTF/2019/rev/High_Quality_Checks/high_quality_checks" \
    6f9ff36334b1c8be130f5fd13d6d77c1de6f546512d1421370fc874948d6e37c
fetch angstrom_guess_the_flag/guess_the_flag "$ARCHIVE/angstromCTF/2024/rev/Guess_the_Flag/guess_the_flag" \
    b2d1ba18d7fcc3ef5e9c0c09ac07ae7d01519ee5cfb2fdfc8ba88b8e9d7877d6
fetch angstrom_autorev_assemble/autorev_assemble "$ARCHIVE/angstromCTF/2020/rev/Autorev_Assemble/autorev_assemble" \
    0c1db256e64f3df76a174ed3983b7836d5f0f6b71439574fb27a00a0b7316bcf
fetch redpwn_check/challenge "$ARCHIVE/redpwn/2022/rev/check/challenge" \
    a1f18fee801dbd562e410497ea26541b86839eec8f344abfea87ab8040a25c52
fetch spaceheroes_acheron/Acheron "$ARCHIVE/SpaceHeroes/2023/rev/Acheron/Acheron" \
    1f366c28327f9de41bc31a73cac9cb6b968ed4b0263124f703597d4707a11476
fetch irisctf_baby_rev/baby_baby_rev "$ARCHIVE/IrisCTF/2023/rev/baby_rev/baby_baby_rev" \
    b1cf9d9af5ec817b7051eadd1abcb6b7f97f938df0d14c28a3bbe99395e995be
fetch heroctf_scarface/scarface "$ARCHIVE/HeroCTF/2023/rev/Scarface/scarface" \
    0d626cb5565646e601861ac4481d4481b16d6e9cd713577328efc20b71f2cc75
fetch thjcc_pocketvm/chall "$ARCHIVE/THJCC/2026/rev/PocketVM/chall" \
    dda09c3047ed9fb213bcb595957065bf8f1f533c7edbbb1bf9d4e8e3ce93df44
fetch thjcc_super_baby_reverse/THJCC_Super_Baby_Reverse \
    "$ARCHIVE/THJCC/2026/rev/Super_baby_reverse/THJCC_Super_Baby_Reverse" \
    b9469757fea9dfa95083ae0d059e4a88a58250f7062d33c71327b46dfcfed511
fetch tscctf_link_start/chal "$ARCHIVE/TSCCTF/2025/rev/Link_Start/chal" \
    3a5a06329deb1b209d2ff4a88241618c70d2ecba31035fd0d02259cda26b791a
fetch wreckctf_flag_checker/chal "$ARCHIVE/WRECKCTF/2022/rev/flag-checker/chal" \
    4a53637b9e16eada5f1d6915ee06f262bd10e697a5c021adcb624c43495c4324
fetch n00bzctf_welcome/chal "$ARCHIVE/n00bzCTF/2023/rev/Welcome/chal" \
    f8c29ae6069f002e98eecc1b313dd3cc26d5add6bc586e0d9f16427f7406f7a7
fetch angstrom_checkers/checkers "$ARCHIVE/angstromCTF/2023/rev/checkers/checkers" \
    f0dbcf2e7bd063c49de33b14e5360c79c6b7c669af69a88983c649b8da6a9245
fetch sunshinectf_baseic/BASEic "$ARCHIVE/SunshineCTF/2025/rev/BASEic/BASEic" \
    066d19861c781164a49ad6951752144a0d87972c6a42ce4d743da2f4ea36bab9
fetch bluehens_intro_to_reverse/flagchecker "$ARCHIVE/BlueHens/2024/rev/Training_Problem_Intro_to_Reverse/flagchecker" \
    4f9b9fff59a5ecdf6f0cd721b2a2c009c6d8bc06edf795ea567c5062b0f91250
fetch foobarctf_babyrev/chall "$ARCHIVE/FooBarCTF/2022/rev/BabyRev/chall" \
    033ae1c8fab31d584ec0a5f3103b83a4a07c1d4ca4ab9b3cfb08f6688042bfb5
fetch metactf_revvy_chevy/chall "$ARCHIVE/MetaCTF/2021/rev/Revvy_Chevy/chall" \
    2aa7624288fa4cbdcdd64a1bcdf1d35bcb203fc497f9b4f1f32b70e45b9cc7b1
fetch foobarctf_cipher_maze/chall "$ARCHIVE/FooBarCTF/2025/rev/Cipher_Maze/chall" \
    dcdb5de0b998e22fe9d47b2fe6f888ff37e0068638993a6145e864bfb74e3ccd
fetch metactf_no_strings/strings "$ARCHIVE/MetaCTF/2021/rev/There_Are_No_Strings_on_Me/strings" \
    90e5536f4be66c48cd3d17359f5a4cb7a2f9b7fcb23e7a102dc5d0656f718aad
fetch rarctf_verybabyrev/verybabyrev "$ARCHIVE/RaRCTF/2021/rev/verybabyrev/verybabyrev" \
    87805f86d9491875d16d3b74125566379fe7bb76f6a4a009d40c9cf83bd87f69
fetch ricerca_crackme/crackme "$ARCHIVE/Ricerca/2023/rev/crackme/crackme" \
    0e1b69e1f57356dfdf416e73431d06ca6ae5a076266d271b80df89ff8a12e027
fetch idekctf_intro_to_gdb/Intro_to_GDB "$ARCHIVE/idekCTF/2021/rev/Intro_To_GDB/Intro_to_GDB" \
    0053bd2013b7a07a662bb56363d7f14ae59584ce555d1ce87f82d898cd5095ed
fetch ijctf_sanity/sanity "$ARCHIVE/IJCTF/2021/rev/Sanity/sanity" \
    6df1b3479f868b39eabdcb52a665fd2b6fd48cac755863cb39a9f69656c2bbe7
fetch litctf_minimalist/minimalist "$ARCHIVE/LexingtonInformaticsTournament/2022/rev/minimalist/minimalist" \
    d64e0e7e15b44558889241ba9d404c1ba2c39c8cd55eb29d627af8e03c7b5a8b
fetch litctf_addition/addition "$ARCHIVE/LexingtonInformaticsTournament/2022/rev/addition/addition" \
    767194e36e6b32a114676187953c791b496287c203cb7b1467ce40c5d4c20768
fetch litctf_sequence_lock/seqlock "$ARCHIVE/LexingtonInformaticsTournament/2026/rev/sequence_lock/seqlock" \
    a180b827aa361f32ce1fb19cbd95b8b41c2262f3fc4b2634b1b588d873b61195
fetch l3akctf_hidden/hidden "$ARCHIVE/L3akCTF/2024/rev/Hidden/hidden" \
    86d0940167bf29453256e52679a3bba8790979fb4222e9443231561b776d60be
fetch l3akctf_angry/angry_patched_skill_issues "$ARCHIVE/L3akCTF/2024/rev/Angry/angry_patched_skill_issues" \
    8184fa1b6334197d6804644dfd7bee96b4091f6a43443a6a995382a1c978b1f8
fetch gdgalgiers_traditions/prog "$ARCHIVE/GDGAlgiers/2022/rev/traditions/prog" \
    819efb62207f1d305a031403f9fda5b3aa9f88286f4035baaaee84f6547a52ec
fetch digitaloverdose_vault/vault "$ARCHIVE/DigitalOverdose/2022/rev/vault/vault" \
    c9408672418edfeb93906f3c7d16337ac9e7b25b6d3c76f338a57a397072a624
fetch crewctf_ez_rev/a.out "$ARCHIVE/CrewCTF/2023/rev/ez_rev/a.out" \
    d913fef9a13986eef850d6eaf08679396ade94e15c70de47cbf4ec22e59d6af4
fetch hackappatoi_sanity_rev/sanityrev "$ARCHIVE/Hackappatoi/2022/rev/Sanity_rev/sanityrev" \
    e79c022e7a339335c49b8924cc3fb4e225d803a13fd123f213ee14954cd97e27
fetch_zip cpctf_black_box/chall "$ARCHIVE/CPCTF/2024/rev/black_box/black_box.zip" \
    ab042f7900fdbb5430297255587fe9546a2ff35371a0fcecbec97623699a5a9b files/chall
fetch_zip cpctf_peeping/chall "$ARCHIVE/CPCTF/2024/rev/peeping/peeping.zip" \
    af5240ba3f738c8a579d0e502640fb21fe2dfc2ba96fb279afcd341d2f5b04bd files/chall
fetch_zip cpctf_fortune_teller/chall "$ARCHIVE/CPCTF/2025/rev/Fortune_Teller/rev-fortune_teller.zip" \
    c6733d2fa254fa0f47b8324e537c0896b7d0c8123a1293298eaac7e248549b6c files/chall
fetch_zip cpctf_secret_key/chall "$ARCHIVE/CPCTF/2025/rev/Secret_Key/rev-secret_key.zip" \
    327141f5ab32f367592026d03c38f602c422f3baf21a7593390b9326f490dfe9 files/chall
