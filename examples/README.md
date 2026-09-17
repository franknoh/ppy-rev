# Examples

Real reversing challenges from past CTFs that `ppy-rev solve` answers, most of them with
no hints at all. Each directory has a walkthrough: what the binary checks, the command,
the output, and how the answer is found.

The binaries are other people's challenges, so they are not stored here. `fetch.sh`
downloads each one from a public archive at a pinned commit and checks its SHA-256;
nothing it downloads is run.

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme
```

| Example | Event | Input | Hints | Answer | Time |
|---|---|---|---|---|---|
| [ais3_crackme](ais3_crackme/README.md) | AIS3 crackme | argv[1] | none | `ais3{I_tak3_g00d_n0t3s}` | 2 s |
| [bcactf_flag_checker](bcactf_flag_checker/README.md) | BCACTF 2022 | argv[1] | none | `bcactf{fl4G_Und3rL00keD_e7df9c}` | 2 s |
| [hsctf_keygen](hsctf_keygen/README.md) | HSCTF 2023 | argv[1] | none | `flag{6275745f-7768-6174-5f6c-6f636b3f0000}` | 2 s |
| [google_unbreakable](google_unbreakable/README.md) | Google CTF 2016 | argv[1] | `--flag-format 'CTF{*}'` | `CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}` | 9 s |
| [defcamp_r100](defcamp_r100/README.md) | DefCamp CTF Quals 2015 | stdin | none | `Code_Talkers` | 2 s |
| [imaginaryctf_keycode](imaginaryctf_keycode/README.md) | ImaginaryCTF 2021 | stdin | none | `ictf{wh@t_g00d_i5_@_10ck_!f_th3_l0ck_!s_th3_k3y?}` | 2 s |
| [imaginaryctf_unoriginal](imaginaryctf_unoriginal/README.md) | ImaginaryCTF 2024 | stdin | none | `ictf{just_another_flag_checker_a3465d5e5ee234ba}` | 2 s |
| [byuctf_reveng](byuctf_reveng/README.md) | BYUCTF 2023 | stdin | none | `She turned me into a newt` | 2 s |
| [lactf_string_cheese](lactf_string_cheese/README.md) | LA CTF 2023 | stdin | none | `blueberry` | 2 s |
| [lactf_shattered_memories](lactf_shattered_memories/README.md) | LA CTF 2024 | stdin | none | `lactf{not_what_forgive_and_forget_means}` | 2 s |
| [lactf_ctfd_plus](lactf_ctfd_plus/README.md) | LA CTF 2023 | stdin | none | `lactf{m4yb3_th3r3_1s_s0m3_m3r1t_t0_us1ng_4_db}` | 4 s |
| [uiuctf_tedious](uiuctf_tedious/README.md) | UIUCTF 2021 | stdin | none | `uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}` | 4 s |
| [knightctf_flag_vault](knightctf_flag_vault/README.md) | KnightCTF 2022 | stdin | none | `abracadabrahahaha` | 5 s |
| [buckeyectf_angry](buckeyectf_angry/README.md) | BuckeyeCTF 2022 | stdin | none | `buckeye{st!ll_b3tt3r_th4n_strfry}` | 6 s |
| [ductf_no_strings](ductf_no_strings/README.md) | DownUnderCTF 2021 | stdin | `--flag-format 'DUCTF{*}' --charset printable` | `DUCTF{stringent_strings_string}` | 6 s |
| [imaginaryctf_stings](imaginaryctf_stings/README.md) | ImaginaryCTF 2021 | stdin | none | `ictf{str1ngs_4r3nt_h1dd3n_17b21a69}` | 8 s |
| [picoctf_bbbbloat](picoctf_bbbbloat/README.md) | picoCTF 2022 | stdin | `--goal-address 0x1014d6` | `549255` | 8 s |
| [lactf_patricks_paraflag](lactf_patricks_paraflag/README.md) | LA CTF 2025 | stdin | none | `lactf{the_flag_got_lost_in_infinity}` | 9 s |
| [csaw_beleaf](csaw_beleaf/README.md) | CSAW CTF Quals 2019 | stdin | `--length 33` | `flag{we_beleaf_in_your_re_future}` | 150 s |

Any of them can also be lifted to PPy and run again from there, as
[ais3_crackme](ais3_crackme/README.md) shows.

Times are with the Ghidra analysis already cached; the first run of a binary adds about
five seconds for it. Answers that are not flags are passwords the program then turns into
one, or the number it wants.
