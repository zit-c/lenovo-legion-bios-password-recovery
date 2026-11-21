# Obtaining a current image: the tested Windows procedure

This is a documented procedure for one owner-confirmed case, not a zero-risk
recipe. **The actual H2OFFT step loads an old driver with a published security
issue and invokes SMI.** Package extraction and the Python verifier are offline
file operations. Decide whether to accept the separate hardware risk before
step 5. Do not execute this procedure on a machine you do not own or administer
with explicit authorization.

## 1. Match the tested configuration

The successful case was Legion 5 17ACH6H (82JY), AMD Ryzen 5 5600H, GKCN65WW.
Windows booted normally; BIOS setup requested a System Password. This is not a
procedure to downgrade or update another BIOS. The exact Windows build and
driver-security policy of the successful case are not specified.

Use a charged battery and stable AC power. Close other firmware tools. Avoid
sleep, hibernation, shutdown and power loss while H2OFFT is active. Do not alter
BIOS security settings, disable driver-signature enforcement, turn off memory
integrity, or add driver-policy exceptions to make this work. If Windows blocks
the driver, stop.

## 2. Obtain the official package as a file

- [Lenovo BIOS support page DS549277](https://support.lenovo.com/us/en/downloads/ds549277).
- [Official GKCN65WW package](https://download.lenovo.com/consumer/mobiles/gkcn65ww.exe).
- [Python downloads](https://www.python.org/downloads/) if Python is not already available.
- [7-Zip downloads](https://www.7-zip.org/download.html) if an archive reader is needed.

Save the package under `private/vendor/gkcn65ww.exe` in this repository.
Download it as data; **do not double-click it or run its installer**, including
so-called extraction switches that execute the installer. A current support
page may offer a different version; this extractor accepts only the exact
GKCN65WW package below.

In ordinary PowerShell, from the repository directory:

```powershell
Get-FileHash -LiteralPath ./private/vendor/gkcn65ww.exe -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath ./private/vendor/gkcn65ww.exe |
    Select-Object Status, @{Name='Signer';Expression={$_.SignerCertificate.Subject}}
```

Expected package SHA-256:

```text
4176f794a811f882ea312c0d8f3ebc711db4c5a8b1bc92dc7301898d3220c1a0
```

The investigated container had a valid Lenovo Authenticode signature. Stop on
a hash mismatch or invalid signature. A matching hash identifies the examined
file; it is not a substitute for trusted download provenance and signature
validation. Offline revocation checks may be inconclusive; do not simply
override a validation failure.

## 3. Extract statically, without running the package

This exact container was not directly readable by the archive-reader version
used in the original investigation. The included narrow extractor reconstructs
its nested 7z archive as data, with a pinned input hash, bounded decompression
and archive-header CRC checks. It is not a generic Inno Setup unpacker.

```powershell
python scripts/extract_gkcn65ww.py private/vendor/gkcn65ww.exe private/vendor/inner.7z
```

Use an independently installed official 7-Zip to test that archive, then
extract all its contents into `private/vendor/gkcn65ww/`. Run its `7z` command
from PATH, or select the same archive in the 7-Zip application:

```powershell
7z t ./private/vendor/inner.7z
7z x ./private/vendor/inner.7z -o./private/vendor/gkcn65ww
```

Stop on any CRC/error output or extraction conflict. These commands operate on
archives only. Do not substitute an executable self-extractor. The Python
extractor will refuse an existing output file; do not overwrite earlier data.

## 4. Keep and verify the complete original bundle

Compare the extracted files against the [official-package inventory](OFFICIAL_PACKAGE.md).
It lists hashes of vendor-distributed files, not private laptop data. Keep all
17 files together, including H2OFFT-W.exe, H2OFFT64.sys, H2OFFT32.sys, WDFInst.exe,
H2OFFT.inf, H2OFFT.cat, platform.ini, OEM components and Microsoft VC90 runtimes.
Do not edit platform.ini, replace drivers with files from another package, or
delete components to try to suppress behavior. BIOS.fd is the vendor image,
not your current personal dump.

The original tool is H2OFFT-W **6.28**, its x64 SYS resource version is **2.0.0.1**.
The original EXE itself was unsigned; its provenance was established from the
signed Lenovo container and verified archive. The original x64 driver and
catalogue had valid signatures. Check the SYS and CAT with
`Get-AuthenticodeSignature` as well. A valid signature does not guarantee that
Windows will permit loading the driver or that it is free of vulnerabilities.

Read [INSYDE-SA-2025010](https://www.insyde.com/security-pledge/sa-2025010/):
CVE-2025-12050/12051 concern H2OFFT drivers, and mobile 6.76.00+ is the stated
fixed baseline. Do not assume readback avoids driver exposure. Conversely,
the CVE does not mean a read operation necessarily rewrites BIOS. This project
does not offer a tested newer replacement for GKCN65WW.

## 5. Optional manual H2OFFT readback

Only this step needs elevated Windows permissions. Stop here if loading the
old driver is unacceptable. It may install/configure a driver service and write
driver files or logs in Windows. It is not an operation that leaves every part
of Windows unchanged.

The confirmed syntax is:

```text
H2OFFT-W.exe <output-file> /g
```

The output filename must immediately precede `/g`; `/g <file>` is not the tested
syntax. `-g` is an equivalent spelling in this build. `/g` selects Read Current
ROM rather than a flash operation. It still executes common initialization,
OEM hooks and SMM handlers; absence of a flash-write call in the read loop does
not establish absence of all transient side effects.

Open PowerShell as administrator, navigate to the repository, and deliberately
run the following block only if you accept that risk. It creates a fresh output
directory; an existing directory causes an error before H2OFFT starts.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $toolDir = (Resolve-Path -LiteralPath './private/vendor/gkcn65ww').Path
    $dumpDir = Join-Path (Get-Location).Path 'private/dumps/read-001'
    New-Item -ItemType Directory -Path $dumpDir | Out-Null
    $dumpFile = Join-Path $dumpDir 'current.bin'
    Start-Process -FilePath (Join-Path $toolDir 'H2OFFT-W.exe') `
        -WorkingDirectory $toolDir `
        -ArgumentList ('"' + $dumpFile + '" /g') -Wait -PassThru
}
```

Do not run the EXE with no arguments, select an update image, add force flags,
or approve any firmware-update/reboot prompt. If those appear, cancel and stop.
On an IHISI or driver error, stop rather than retrying with security settings
disabled. A process exit code alone does not prove a complete successful read.

## 6. Validate the resulting file offline

After H2OFFT has finished, use an ordinary, non-elevated shell:

```powershell
python scripts/verify_dump.py private/dumps/read-001/current.bin
```

Expected for the recorded case: 16,777,216 bytes, three valid FV headers, an
HFDM candidate at `0xEA8000`, and one LSPE marker. Other results require review,
not blind decoding or reflashing. The vendor update container is a different
size and cannot replace a current dump.

The verifier prints SHA-256, structural metadata and warnings; it does not
print paths or credentials. No public hash can establish that your individual
dump is correct. Store the dump and output privately. Do not attach either
to a GitHub issue. Continue with the included [offline recovery guide](RECOVERY.md)
and decoder only after reviewing those integrity results. The decoder does not
run H2OFFT or obtain another dump.
