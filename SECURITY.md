# Security and private information

Do not upload BIOS dumps, decoded or encoded credentials, LSPE contents,
serial numbers, UUIDs, device certificates, screenshots of private firmware
data, or unreviewed diagnostic output. A dump may contain substantially more
than the password under investigation.

This release contains an offline password decoder, with no hardware client.
Decoded bytes, text candidates and the generated JSON file are all secrets.
The result is unencrypted and written only to a new local file. Do not place
it in a synced/public directory. See [the publication decision](docs/PUBLICATION_DECISION.md).

For a non-sensitive bug in the offline tools, describe the problem and Python
version, preferably with an entirely synthetic reproducer. Never attach a real
firmware image. There is no private-reporting mailbox configured for this
unpublished project. Do not put a secret in a public issue while looking for
one. Firmware vulnerabilities should go through the relevant vendor's
disclosure process, not a public credential upload.

Treat the historical H2OFFT command as an opt-in hardware experiment. Do not
disable driver protections or change firmware security policies to make it run.
No project Python script needs administrator privileges.
