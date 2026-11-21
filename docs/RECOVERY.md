# Offline password recovery

Confirmed hardware case: **Lenovo Legion 5 17ACH6H (82JY), Ryzen 5 5600H,
BIOS GKCN65WW only**. Other models/revisions are unsupported. The decoder
requires a local raw dump and performs no firmware writes, hardware calls,
driver loading or network requests. Use only authorized images.

## Commands

Use Python 3.10+ and an ordinary non-administrator shell in this repository:

```powershell
python scripts/verify_dump.py private/dumps/current.bin
python scripts/recover_bios.py private/dumps/current.bin --profile GKCN65WW --output private/recovered/result.json
```

If you followed READBACK.md, use `private/dumps/read-001/current.bin` instead.
These are examples, not included files. No real credential is used in examples.
The output parent directory is created if needed. Existing files cannot be
overwritten, including the input itself. Choose a new private output filename
for another analysis.

Open the JSON file privately using a local editor. Do not paste it into an
issue, cloud document or public chat. Terminal output deliberately omits
credentials, so redirecting stdout will not export the password. There is no
force option, alternate-offset search or automatic BIOS login. The output is
unencrypted: POSIX creation requests owner-only mode, while Windows inherits
the destination directory ACL. The script changes no policies or ACLs. Choose
a private non-synced directory and protect the result like the original dump.

## Algorithm and validation

1. Require profile `GKCN65WW` and raw size `0x1000000` (16 MiB).
2. Check HFDM at `0xEA8000`, geometry `(total=0xC48, header=0x24, entry=0x54)`,
   zero byte sum over the first 28 header bytes, and flash base `0xFF000000`.
3. Parse unique region type GUIDs `f392b582-1f08-4e95-b51d-598b19f6993f` and
   `fa01652a-4942-417a-ae1c-b8fa2bd31a84`. Match offsets `0x5AF000` and
   `0x5AF800`, sizes `0x800` each. These are firmware-format identifiers, not
   machine UUIDs. Missing, duplicate or different mappings fail closed.
4. Check the seven-byte LSPE service record at the end of the combined region
   (`0x5AFFF9`). The first four bytes must spell LSPE. The sum of its first
   five bytes must equal the little-endian 16-bit value at offset +5.
5. XOR the credential prefix with the byte at LSPE +4. The decoded format is
   `[length][payload][checksum]`; the sum of all `length+2` bytes modulo 256
   must be zero. Re-encoding must reproduce the stored bytes. The conservative
   investigated maximum of 16 payload bytes is enforced, not claimed universal.
6. Skip a fully FF region, excluding LSPE in the second region. A valid
   zero-length record is empty. Malformed non-erased records cause failure
   rather than guessed credentials or partial decoded output.

This follows the investigated SysPassword path. Checks do not authenticate
firmware identity or prove a complete SPI read. Selecting a profile is an
explicit assertion, not an automatic model detector; constructed or different
images may match. An erased returned region does not prove the physical laptop
has no password: protected data may not have been returned.

## Secret output fields

- `records`: nonempty validated records.
- `region_index`: original index, not a guaranteed Supervisor/User role.
- `decoded_record_hex`, `payload_hex`: recovered bytes, also secrets.
- `us_unshifted_candidate`: standard PC set-1 key positions mapped to the US
  unshifted layout, or null if any byte is unsupported.
- `uppercase_letters_candidate`: uppercase-letter variant; punctuation is not
  transformed into arbitrary shifted guesses.
- `region_status`: validated, erased/not returned, or empty valid record.
- `source_sha256`: private input fingerprint for local provenance only.

Integrity checks establish the stored bytes, not all keyboard input details.
Other layouts, Shift/Caps state and region-role selection are not universally
established. Unknown bytes are preserved without inventing a text candidate.
In the original owner-confirmed case the recovered candidate opened BIOS setup.
That success is not a guarantee for a different image or machine.

## Errors and exit status

`0`: validated records written to the local result; a warning can still flag
unmapped bytes. `1`: no nonempty valid record. `2`: unsupported profile/layout,
invalid input/checksum, existing output or filesystem failure. Errors do not
include paths or credential bytes. Failed decoding creates no output. A later
filesystem write failure may leave a partial secret file; protect it and choose
a new output name after investigating permissions. Do not brute-force hardware
prompts or alter firmware to compensate for a decoder error.
