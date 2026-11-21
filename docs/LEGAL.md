# License and provenance review

## Original project material

The original Python scripts, synthetic tests and documentation in this release
are offered under MIT. The generic contributor copyright notice avoids
inventing a personal identity. The owner can use a chosen public name in that
notice if desired. MIT does not require publishing a home address or a private
email. [MIT license reference](https://opensource.org/license/mit).

The checker was adapted from the original private research helper. The narrow
extractor was made portable from the original package-specific helper. Both
are original project code, not copied implementations of public password
recovery tools. No upstream password-reader code, LenovoDMIDecryptor code,
firmware module or disassembly is included. The extractor's container/filter
interpretation was previously cross-checked against format behavior described
in the innoextract project; no upstream source text is reproduced here.

The password decoder is a portable adaptation of the original project's
successful private recovery script, using independently analyzed SysPassword
behavior. It contains no original dump hash, real password examples or private
record bytes. HFDM region-type GUIDs and format constants are firmware-format
facts, not device-specific identifiers. The keyboard mapping is constructed
from standard PC set-1 key positions; it is not copied from another recovery
project. Original decoder source and synthetic tests are covered by MIT.

## Vendor material is not MIT-licensed here

Lenovo BIOS images, Insyde H2OFFT, SYS drivers, DLLs, INF/CAT files and bundled
Microsoft runtimes are third-party software. They are not included and the
project's MIT license does not grant rights to them. Obtain them from the
official vendor and retain their accompanying terms.

Lenovo's published license limits copying/distribution and reverse translation,
with applicable-law qualifications. Linking to an official download does not
relicense it. This review has not established the exact agreement accepted by
every user or jurisdiction-specific permission for firmware reverse
engineering. The applicable package terms and local law remain controlling;
this is not a legal clearance of every possible use.

References:

- [Lenovo license, products sold on or after July 22, 2022 unless otherwise specified](https://support.lenovo.com/us/en/solutions/ht100141-lenovo-license-agreement-l505-0009-06).
- [Lenovo published license text](https://pcsupport.lenovo.com/pr/en/solutions/ht104242/).
- [Official BIOS support page](https://support.lenovo.com/us/en/downloads/ds549277).

7-Zip and Python are optional external prerequisites obtained separately, not
vendored dependencies. See [7-Zip licensing](https://www.7-zip.org/license.txt)
and [Python licensing](https://docs.python.org/3/license.html). No external
Python packages are required. This repository does not redistribute 7-Zip,
Python, their libraries or installers.

Product and company names identify the tested configuration. No logos or
endorsement claims are included. Future third-party code must receive a new
license/provenance review. The security decision for a decoder is separate
from the MIT license on the material actually included.
