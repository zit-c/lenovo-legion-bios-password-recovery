# Local release review

Updated November 21, 2026 for the owner's decision to include the original
offline decoder. Nothing was uploaded; no remote repository was created.
The private research files were not modified.

The publication inventory contains 20 UTF-8 text files. It includes the decoder,
its synthetic tests and the recovery guide. It contains no vendor binaries,
firmware image, real credential, encoded private record, original dump hash,
Windows account path, serial number or machine UUID. HFDM region-type GUIDs
are firmware-format facts, not device-specific identifiers.

## Checks for this revision

- 31 synthetic unit tests passed, including recovery, both regions, erased and
  empty records, unmapped key positions, XOR boundary keys, unsupported profile
  and size, invalid geometry/base/map, duplicate GUIDs, overlong records,
  corrupt checksums, secret-free terminal output, immutable input and exclusive
  local output. No real firmware or credential is a test fixture.
- The public inventory audit passed. Every public file was checked locally for
  matches to the original private password candidates, encoded/decoded record
  representations, private dump hash and research paths. No matches were found.
  Private comparison values were not added to the repository.
- Local documentation links and the exact file inventory were checked.
- Git ignore behavior was checked in an isolated temporary repository. Public
  files remain stageable; representative dumps, result JSON, vendor binaries
  and logs are ignored. Git history is not covered by this check.
- Prior static extraction/verification checks remain documented: the portable
  extractor reproduced the verified official archive; the verifier reported
  the original image's expected structure. No H2OFFT or hardware operation was
  repeated for this revision. The new portable decoder was tested using
  synthetic data; the original underlying algorithm and candidate were already
  confirmed in the owner's successful hardware case.

## Provenance and publication scope

The decoder is adapted from the original project's recovery helper, not copied
from a third-party decoder. Original source, synthetic tests and documentation
remain MIT-licensed. Vendor software is linked, not redistributed. LEGAL states
the limits of the license review; it is not jurisdiction-specific legal clearance.
The owner explicitly approved decoder inclusion in PUBLICATION_DECISION.

No technical fix is outstanding for this scope after the listed checks. Public
attribution can be customized before the first commit. Review any new edits,
staged files, Git author metadata and release attachments before uploading.
