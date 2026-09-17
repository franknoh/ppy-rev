# Examples

Real reversing challenges from past CTFs that `ppy-rev solve` answers with at most one
hint. Each directory has a walkthrough: what the binary checks, the command, the output,
and how the answer is found.

The binaries are other people's challenges, so they are not stored here. `fetch.sh`
downloads each one from a public archive at a pinned commit and checks its SHA-256; nothing
it downloads is run.

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme
```

| Example | Event | Input | Hint | Answer | Time |
|---|---|---|---|---|---|
| [ais3_crackme](ais3_crackme/README.md) | AIS3 crackme | `argv[1]` | none | `ais3{I_tak3_g00d_n0t3s}` | 7 s |
| [defcamp_r100](defcamp_r100/README.md) | DefCamp CTF Quals 2015 | stdin | none | `Code_Talkers` | 7 s |
| [google_unbreakable](google_unbreakable/README.md) | Google CTF 2016 | `argv[1]` | `--flag-format 'CTF{*}'` | `CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}` | 14 s |
| [picoctf_bbbbloat](picoctf_bbbbloat/README.md) | picoCTF 2022 | stdin | `--goal-address 0x1014d6` | `549255` | 12 s |
| [csaw_beleaf](csaw_beleaf/README.md) | CSAW CTF Quals 2019 | stdin | `--length 33` | `flag{we_beleaf_in_your_re_future}` | 100 s |

Times include Ghidra's first analysis of the binary, about five seconds; later runs read
the analysis from the cache.
