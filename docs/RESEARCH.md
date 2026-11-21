# Evidence and limits

## Outcome reported by the owner

On one Legion 5 17ACH6H (82JY), Ryzen 5 5600H, GKCN65WW, H2OFFT-W 6.28 read
a 16 MiB current image from Windows. Offline analysis validated three firmware
volume headers, found HFDM and an LSPE marker, recovered a stored record, and
checked its internal integrity and reversible representation. The owner then
confirmed that the recovered password opened BIOS setup. Reflashing and an
external programmer were not needed in this case.

No image, credential length, credential bytes, device identifier or hash of
the private dump is published. The outcome is a single owner-confirmed case;
other users cannot independently reproduce the private evidence from this
repository, and no second-device confirmation is claimed.

## What was established statically

The official package's readback parser accepts a filename immediately before
`/g` (also `-g`). Its current-ROM branch obtains flash information and performs
block reads through IHISI 0x14 before saving the result. No erase/write call was
identified in that read loop. Shared startup/cleanup, OEM hooks and the SMM
handlers remain part of the operation; readback is not a proof that no state
changes anywhere.

The firmware's SysPassword provider and HFDM/LSPE structures were relevant to
the private recovery. This public release includes the original offline
decoding procedure in recover_bios.py and RECOVERY.md, but does not reproduce
vendor disassembly or the owner's private records.

## Public verifier boundaries

The checker validates candidate firmware-volume header bounds and 16-bit
header sums, checks candidate HFDM header geometry and its observed header
checksum, and counts LSPE markers without interpreting their contents.
Signature matches can occur inside code or arbitrary data. A valid header is
not a signed authenticity check. An LSPE marker does not prove a valid service
record, and its absence does not prove there is no password.

The expected 16 MiB size is specific to the tested profile, not every Lenovo.
Wrong-sized and uniformly filled inputs fail preliminary checks. Passing does
not prove full SPI coverage, permission to read protected data, or recoverable
credentials. SHA-256 identifies the file only; there is no public correct hash
for an individual machine's current image. Independently captured dumps can
differ because firmware state changes.

## Driver finding

The old driver contained a registry-read pattern consistent with the issue
described by Insyde. Local exploitability against the owner's Windows policy
and registry permissions was not demonstrated. The successful read does not
establish that the driver is safe to load. The advisory recommends mobile
H2OFFT 6.76.00 or newer, but a newer client from a different OEM platform is
not automatically compatible with GKCN65WW.

Source: [Insyde INSYDE-SA-2025010](https://www.insyde.com/security-pledge/sa-2025010/).
