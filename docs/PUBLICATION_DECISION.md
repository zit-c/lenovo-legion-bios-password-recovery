# Decision: include the original offline decoder

Status: approved by the project owner for this prepared public release. This
supersedes the earlier deferral. Nothing has been uploaded during preparation.

The owner explicitly selected publication of the original recovery algorithm
because password recovery is the project's main purpose. The release now
includes local-file HFDM/LSPE parsing, XOR reversal, integrity checks and
keyboard candidates. A successful recovery and BIOS login were confirmed on
one Legion 5 17ACH6H (82JY), GKCN65WW only. The portable release has synthetic
tests; no second-device confirmation is claimed.

A decoder can expose credentials from an acquired or stolen dump. Use it only
for systems you own or are explicitly authorized to administer. This is a use
policy, not an enforceable ownership check. Public release makes the algorithm
available independently of the intended repair use case.

Boundaries: explicit narrow profile, strict layout and integrity checks, local
input/output, no hardware access, no firmware patching, no network requests and
no automatic login attempts. Credentials go only into a new local file, never
stdout/stderr. No real image, credential, encoded record or private identifier
is distributed. All fixtures are invented. These controls reduce accidental
leakage; they cannot prevent misuse by someone already holding a dump.

This decision is not vendor approval, legal clearance, a CVE assignment or a
claim of completed coordinated disclosure. None of those has been established
for the credential-storage finding. See [LEGAL.md](LEGAL.md) for license and
jurisdictional limits, and [SECURITY.md](../SECURITY.md) for reporting hygiene.
