# legion-bios-recovery

A documented BIOS password recovery case on a Lenovo Legion 5 17ACH6H (82JY), with a portable offline password-record decoder, dump verification and static extraction of the exact official update package.

**This release includes the original project's password decoder for the investigated GKCN65WW layout.** It operates on a local image only; there is no firmware writer or hardware-access driver. Read the [recovery guide](docs/RECOVERY.md) and [publication decision](docs/PUBLICATION_DECISION.md).

## Confirmed on one laptop

| Component | Tested configuration |
| --- | --- |
| Laptop | Lenovo Legion 5 17ACH6H, machine type 82JY |
| CPU | AMD Ryzen 5 5600H |
| BIOS | GKCN65WW |
| Readback utility | H2OFFT-W 6.28 from the official Lenovo package |
| Windows driver in that package | H2OFFT64.sys, file version 2.0.0.1 |
| Raw dump size | 16,777,216 bytes (16 MiB) |
| Offline observations | Three valid firmware-volume headers, an HFDM structure, one LSPE marker |
| Recovery outcome | A stored password record was recovered; the owner confirmed the recovered password successfully opened BIOS setup |

Windows still booted normally, while entering BIOS setup requested a forgotten System Password. A current BIOS image was read from Windows, analyzed offline, and used to recover access. No BIOS reflash or external programmer was needed. The exact Windows build and security-policy state were not recorded for publication.

**Compatibility is established only for this individual configuration.** Similar model names, another GKCN revision, or another Insyde firmware do not establish compatibility. Recovery of one password does not establish recovery of every password type, HDD password, or disk-encryption key.

## Important risks before readback

The Python tools in this repository operate only on ordinary local files. Obtaining a dump with H2OFFT is a separate privileged operation: it loads a kernel driver and invokes firmware SMI handlers. Readback is not equivalent to a harmless file copy; it can affect transient controller/session state and may hang the machine.

Insyde identifies potential buffer-overflow vulnerabilities in H2OFFT drivers and recommends mobile H2OFFT 6.76.00 or newer. The successful case used older 6.28. This repository records that historical outcome, not a recommendation to load a known-risk driver. A newer official 6.76 package was found for a different Lenovo platform; its compatibility with this Legion was not confirmed. Do not mix components or bypass Windows protections. See [Insyde INSYDE-SA-2025010](https://www.insyde.com/security-pledge/sa-2025010/) and the [readback guide](docs/READBACK.md).

## Start with the offline tools

Python 3.10 or newer with its standard library is sufficient. No pip dependencies or administrator privileges are required for these tools. Commands assume the repository is the current directory and a suitable Python is available as `python`.

```powershell
python scripts/verify_dump.py --help
python scripts/verify_dump.py private/dumps/current.bin
python scripts/recover_bios.py private/dumps/current.bin --profile GKCN65WW --output private/recovered/result.json
```

The verifier reports size, SHA-256, candidate firmware-volume headers and their checksums, HFDM header candidates, and the number of LSPE markers. It does not show the input filename, decode credentials, print firmware bytes, or contact a network. Treat generated reports, including dump hashes, as private. Exit status 0 means preliminary structural checks passed, 1 means review is required, and 2 means an input/CLI error occurred.

Read [how to obtain the dump](docs/READBACK.md) before considering any H2OFFT command. Do not run the update installer to extract its contents.

The decoder requires explicit selection of `GKCN65WW`, validates the observed HFDM layout and checksums, validates LSPE, reverses the record XOR and validates the record checksum and re-encoding. It writes credential bytes and US keyboard candidates to the requested **new local file**, without printing them or overwriting an existing result. An unsupported layout causes an error rather than guessed offsets.

Only the original case on Legion 5 17ACH6H (82JY), GKCN65WW is hardware-confirmed. The portable release has synthetic tests; it is not claimed to have been tested on a second laptop. See [RECOVERY.md](docs/RECOVERY.md) for output fields, errors, keyboard interpretation and the conservative length limit.

## How the research worked

Static analysis of copies of the firmware identified the SysPassword provider, HFDM flash-map structures and an LSPE service record. The current image contained a recoverable stored record, rather than only a one-way password hash. Offline integrity checks and re-encoding supported the recovered record. Its keyboard interpretation was then independently confirmed by the owner's successful BIOS login.

These observations do not show that the firmware password is exposed through the standard Windows UEFI-variable API, nor that arbitrary flash regions are always readable. A correct file length or a valid header checksum does not prove a complete, authentic read. The public checker deliberately does not parse password records or interpret LSPE payloads.

The original dump, password, encoded record, private hashes, serial numbers, screenshots, disassembly, and vendor binaries are not included. No sample BIOS image is provided. Tests construct synthetic structures in memory.

## Project contents

- [Readback guide](docs/READBACK.md): official sources, static extraction, component checks, historical command and risks.
- [Research notes](docs/RESEARCH.md): evidence and remaining limits.
- [Recovery guide](docs/RECOVERY.md): offline commands, algorithm and private output handling.
- [Publication decision](docs/PUBLICATION_DECISION.md): explicit scope and risks of publishing the decoder.
- [Legal and provenance notes](docs/LEGAL.md): scope of MIT and third-party licensing.
- [Publishing guide](docs/PUBLISHING.md): first-repository checklist, description and topics.
- [Local release review](docs/RELEASE_CHECK.md): completed checks and remaining decisions.
- `scripts/verify_dump.py`: offline structural checks.
- `scripts/recover_bios.py`: offline HFDM/LSPE password-record recovery.
- `scripts/extract_gkcn65ww.py`: narrow, hash-pinned static package extraction.
- `scripts/audit_publication.py`: strict publication-file inventory and privacy checks.

Run the offline tests and publication audit:

```powershell
python -B -m unittest discover -s tests -v
python -B scripts/audit_publication.py
```

## Privacy and contributions

Keep every dump, downloaded package, extracted binary and generated report under the ignored `private/` directory or entirely outside this repository. `.gitignore` cannot remove already committed material. Never upload firmware images or credential bytes in issues, pull requests or releases. See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

Original project code and documentation are offered under [MIT](LICENSE). Lenovo/Insyde software is separately licensed and is linked, not redistributed. This project is independent and is not endorsed by Lenovo or Insyde.
