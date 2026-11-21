# Contributing

Use Python 3.10+ and the standard library. Run the synthetic tests and the
publication audit documented in the README before submitting changes.

Keep tests synthetic. Do not submit firmware binaries, disassembled vendor
modules, passwords, encoded records, identifiers or real-device report files.
Do not add automatic downloads, kernel-driver loading, firmware writes, SMI
clients, or broader decoding profiles without revisiting the publication
decision and documenting evidence. The included GKCN65WW decoder must keep
secret output local and fail closed on invalid structures.

Describe compatibility precisely: model, CPU family, BIOS revision and what was
actually observed. Do not infer a successful recovery from a parser finding a
marker. Do not submit code copied from another project without its provenance
and a compatible license. Contributions are intended to be under this
project's MIT license.
