# Examples

60 reversing challenges from past CTFs that `ppy-rev solve` answers, most of them with no
hints at all. Each directory has a walkthrough: what the binary checks, the command, the
output, and how the answer is found.

The binaries are other people's challenges, so they are not stored here. `fetch.sh` downloads
each one from a public archive at a pinned commit and checks its SHA-256; nothing it downloads
is run. `check.sh` then solves every example with the command its README documents and compares
the answer. With `VERIFY=1` it also runs each answer on the real binary, in the sandbox.

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme
examples/check.sh                     # all of them, about ten minutes
VERIFY=1 examples/check.sh            # and check each answer against the binary itself
```

| Example | Event | Input | Hints | Answer | Time |
|---|---|---|---|---|---|
| [cpctf_secret_key](cpctf_secret_key/README.md) | CPCTF 2025 | stdin | none | `reversing` | 1 s |
| [ais3_crackme](ais3_crackme/README.md) | AIS3 crackme | argv[1] | none | `ais3{I_tak3_g00d_n0t3s}` | 2 s |
| [angstrom_checkers](angstrom_checkers/README.md) | ångstromCTF 2023 | stdin | none | `actf{ive_be3n_checkm4ted_21d1b2cebabf983f}` | 2 s |
| [b01lers_crackme](b01lers_crackme/README.md) | b01lers CTF 2022 | stdin | none | `bctf{133&_letmein_123}` | 2 s |
| [b01lers_crackme_2](b01lers_crackme_2/README.md) | b01lers CTF 2022 | stdin | none | `bctf{4lg3br4!}` | 2 s |
| [bcactf_flag_checker](bcactf_flag_checker/README.md) | BCACTF 2022 | argv[1] | none | `bcactf{fl4G_Und3rL00keD_e7df9c}` | 2 s |
| [bluehens_intro_to_reverse](bluehens_intro_to_reverse/README.md) | BlueHens CTF 2024 | stdin | none | `udctf{r3v3ng3_101}` | 2 s |
| [defcamp_r100](defcamp_r100/README.md) | DefCamp CTF Qualification 2015 | stdin | none | `Code_Talkers` | 2 s |
| [hackappatoi_sanity_rev](hackappatoi_sanity_rev/README.md) | Hackappatoi CTF 2022 | argv[1] | none | `hctf{It_h4s_b33N_345Y}` | 2 s |
| [heroctf_scarface](heroctf_scarface/README.md) | HeroCTF 2023 | stdin | none | `S4y_H3lL0_t0_mY_l1ttl3_FR13ND!!` | 2 s |
| [hsctf_keygen](hsctf_keygen/README.md) | HSCTF 2023 | argv[1] | none | `flag{6275745f-7768-6174-5f6c-6f636b3f0000}` | 2 s |
| [imaginaryctf_keycode](imaginaryctf_keycode/README.md) | ImaginaryCTF 2021 | stdin | none | `ictf{wh@t_g00d_i5_@_10ck_!f_th3_l0ck_!s_th3_k3y?}` | 2 s |
| [l3akctf_hidden](l3akctf_hidden/README.md) | L3akCTF 2024 | argv[1] | none | `L3AK{b4by_sT3Ps}` | 2 s |
| [litctf_minimalist](litctf_minimalist/README.md) | LIT CTF 2022 | stdin | none | `LITCTF{Wh0_n33ds_a11_th0sE_f4ncy_1nstructions?}` | 2 s |
| [metactf_no_strings](metactf_no_strings/README.md) | MetaCTF 2021 | stdin | none | `MetaCTF{this_is_the_most_secure_ever}` | 2 s |
| [spaceheroes_acheron](spaceheroes_acheron/README.md) | Space Heroes 2023 | stdin | none | `NENWSSEWSNENSSWEENWSNNESS` | 2 s |
| [tamuctf_nope](tamuctf_nope/README.md) | TAMUctf 2023 | argv[1] | none | `gigem{fUnky_1nlin3_4sm}` | 2 s |
| [wreckctf_flag_checker](wreckctf_flag_checker/README.md) | WRECK CTF 2022 | stdin | none | `flag{gdb_1s_y0ur_b35t_fr13nd_6d94620fa6}` | 2 s |
| [angstrom_high_quality_checks](angstrom_high_quality_checks/README.md) | ångstromCTF 2019 | stdin | none | `actf{fun_func710n5}` | 3 s |
| [byuctf_reveng](byuctf_reveng/README.md) | BYUCTF 2023 | stdin | none | `She turned me into a newt` | 3 s |
| [cpctf_peeping](cpctf_peeping/README.md) | CPCTF 2024 | stdin | none | `CPCTF{b3_4_cLa1rv0yANt}` | 3 s |
| [gdgalgiers_traditions](gdgalgiers_traditions/README.md) | GDG Algiers CTF 2022 | stdin | none | `CyberErudites{DA_Cl4$$IC_X0R_X_N07_Th4t_R4nd0m}` | 3 s |
| [imaginaryctf_unoriginal](imaginaryctf_unoriginal/README.md) | ImaginaryCTF 2024 | stdin | none | `ictf{just_another_flag_checker_a3465d5e5ee234ba}` | 3 s |
| [irisctf_baby_rev](irisctf_baby_rev/README.md) | IrisCTF 2023 | stdin | none | `irisctf{microsoft_word_at_home:}` | 3 s |
| [lactf_shattered_memories](lactf_shattered_memories/README.md) | LA CTF 2024 | stdin | none | `lactf{not_what_forgive_and_forget_means}` | 3 s |
| [litctf_addition](litctf_addition/README.md) | LIT CTF 2022 | stdin | none | `LITCTF{add1ti0n_is_h4rd}` | 3 s |
| [metactf_revvy_chevy](metactf_revvy_chevy/README.md) | MetaCTF 2021 | stdin | none | `MetaCTF{pr0p3r_encrypt10n_1snt_s0_e4sy...}` | 3 s |
| [n00bzctf_welcome](n00bzctf_welcome/README.md) | n00bzCTF 2023 | stdin | none | `n00bz{N3v3R_$torE_$ENs1TIV3_1nFOrMa7IOn_P1aiNtexT_In_yoUr_bin4rI3S!!!!!}` | 3 s |
| [rarctf_verybabyrev](rarctf_verybabyrev/README.md) | RaRCTF 2021 | stdin | none | `rarctf{3v3ry_s1ngl3_b4by-r3v_ch4ll3ng3_u535_x0r-f0r_s0m3_r34s0n_4nd_1-d0nt_kn0w_why_dc37158365}` | 3 s |
| [ricerca_crackme](ricerca_crackme/README.md) | Ricerca CTF 2023 | stdin | none | `N1pp0n-Ich!_s3cuR3_p45$w0rD` | 3 s |
| [swampctf_beginner_rev](swampctf_beginner_rev/README.md) | SwampCTF 2024 | stdin | none | `swampCTF{X0R_inv0luti0n_i5_c00l}` | 3 s |
| [cpctf_fortune_teller](cpctf_fortune_teller/README.md) | CPCTF 2025 | stdin | none | `CPCTF{y0u_c4n_s01v3_w1th0ut_r3Ad1nG_4ssembly}` | 4 s |
| [digitaloverdose_vault](digitaloverdose_vault/README.md) | Digital Overdose CTF 2022 | stdin | none | `DOCTF{H4CK3RPR00F}` | 4 s |
| [lactf_ctfd_plus](lactf_ctfd_plus/README.md) | LA CTF 2023 | stdin | none | `lactf{m4yb3_th3r3_1s_s0m3_m3r1t_t0_us1ng_4_db}` | 4 s |
| [lactf_string_cheese](lactf_string_cheese/README.md) | LA CTF 2023 | stdin | none | `blueberry` | 4 s |
| [picoctf_bbbbloat](picoctf_bbbbloat/README.md) | picoCTF 2022 | stdin | `--goal-address 0x1014d6` | `549255` | 4 s |
| [redpwn_check](redpwn_check/README.md) | redpwn CTF 2022 | stdin | none | `hope{oops_all_flag_checkers_64961defe21b15e8}` | 4 s |
| [angstrom_one_bite](angstrom_one_bite/README.md) | ångstromCTF 2019 | stdin | none | `actf{i_think_im_going_to_be_sick}` | 5 s |
| [idekctf_intro_to_gdb](idekctf_intro_to_gdb/README.md) | idekCTF 2021 | stdin | none | `idek{m0m_g3t_th3_c4m3rA!}` | 5 s |
| [imaginaryctf_stings](imaginaryctf_stings/README.md) | ImaginaryCTF 2021 | stdin | none | `ictf{str1ngs_4r3nt_h1dd3n_17b21a69}` | 5 s |
| [knightctf_flag_vault](knightctf_flag_vault/README.md) | KnightCTF 2022 | stdin | none | `abracadabrahahaha` | 5 s |
| [thjcc_super_baby_reverse](thjcc_super_baby_reverse/README.md) | THJCC 2026 | stdin | none | `THJCC{BaBY_r3v3rs3_f0r_beggin3r}` | 5 s |
| [ijctf_sanity](ijctf_sanity/README.md) | IJCTF 2021 | stdin | none | `IJCTF{you_did_not_fall_for_it_right?}` | 6 s |
| [uiuctf_tedious](uiuctf_tedious/README.md) | UIUCTF 2021 | stdin | none | `uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}` | 6 s |
| [cpctf_black_box](cpctf_black_box/README.md) | CPCTF 2024 | stdin | none | `CPCTF{ConS7RucT_A_fl46_b0X}` | 7 s |
| [angstrom_guess_the_flag](angstrom_guess_the_flag/README.md) | ångstromCTF 2024 | stdin | none | `actf{committed_to_the_least_significant_bit}` | 8 s |
| [buckeyectf_angry](buckeyectf_angry/README.md) | BuckeyeCTF 2022 | stdin | none | `buckeye{st!ll_b3tt3r_th4n_strfry}` | 8 s |
| [ductf_no_strings](ductf_no_strings/README.md) | DownUnderCTF 2021 | stdin | `--flag-format 'DUCTF{*}' --charset printable` | `DUCTF{stringent_strings_string}` | 8 s |
| [google_unbreakable](google_unbreakable/README.md) | Google CTF 2016 | argv[1] | `--flag-format 'CTF{*}'` | `CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}` | 10 s |
| [litctf_sequence_lock](litctf_sequence_lock/README.md) | LIT CTF 2026 | stdin | none | `LITCTF{f1bon4cci_ch41ns_ftw}` | 10 s |
| [sunshinectf_baseic](sunshinectf_baseic/README.md) | SunshineCTF 2025 | stdin | none | `sun{c0v3r1ng_ur_B4535}` | 12 s |
| [l3akctf_angry](l3akctf_angry/README.md) | L3akCTF 2024 | stdin | `--flag-format 'L3AK{*}'` | `L3AK{angr_4_l@f3_d0nt_do_i@_m4nU4lly}` | 13 s |
| [angstrom_autorev_assemble](angstrom_autorev_assemble/README.md) | ångstromCTF 2020 | stdin | none | `actf{wr0t3_4_pr0gr4m_t0_h3lp_y0u_w1th_th1s_df93171eb49e21a3a436e186bc68a5b2d8ed}` | 15 s |
| [foobarctf_babyrev](foobarctf_babyrev/README.md) | FooBarCTF 2022 | argv[1] | none | `GLUG{C01nc1d3nc3_c4n_b3_fr3aky_T6LSERDYB6}` | 15 s |
| [thjcc_pocketvm](thjcc_pocketvm/README.md) | THJCC 2026 | stdin | none | `THJCC{71ny_vm_5h311_p4ck}` | 16 s |
| [tscctf_link_start](tscctf_link_start/README.md) | TSCCTF 2025 | stdin | none | `TSC{Y0u_4Re_a_L1nK3d_LI5t_MasTeR_@ka_LLM~~~}` | 16 s |
| [lactf_patricks_paraflag](lactf_patricks_paraflag/README.md) | LA CTF 2025 | stdin | none | `lactf{the_flag_got_lost_in_infinity}` | 21 s |
| [foobarctf_cipher_maze](foobarctf_cipher_maze/README.md) | FooBarCTF 2025 | stdin | none | `x0r_and_l0g1c@l_sh1ft_e@sy_r1gh8??` | 48 s |
| [crewctf_ez_rev](crewctf_ez_rev/README.md) | CrewCTF 2023 | stdin | none | `flag{ez_rev_goes_brrrrr....but_wait_a_seccond_the_format_flag_looks_weird}` | 52 s |
| [csaw_beleaf](csaw_beleaf/README.md) | CSAW CTF Qualification Round 2019 | stdin | `--length 33` | `flag{we_beleaf_in_your_re_future}` | 179 s |
Any of them can also be lifted to PPy and run again from there, as
[ais3_crackme](ais3_crackme/README.md) shows.

Times are with the Ghidra analysis already cached; the first run of a binary adds about five
seconds for it. Answers that are not flags are passwords the program turns into one, or the
number it asks for. This table is generated from the example READMEs by
`scripts/examples_index.py`. One binary, [crewctf_ez_rev](crewctf_ez_rev/README.md), rejects
every input on any glibc but the author's, and its README says so.
