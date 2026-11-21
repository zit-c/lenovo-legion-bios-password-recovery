# Official package inventory

These hashes identify files from the official, publicly distributed GKCN65WW package. They are not hashes of a current device dump. No vendor files are redistributed.

Source: [Lenovo official download](https://download.lenovo.com/consumer/mobiles/gkcn65ww.exe).

Package SHA-256: `4176f794a811f882ea312c0d8f3ebc711db4c5a8b1bc92dc7301898d3220c1a0`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `BIOS.fd` | 18830456 | `2b872ef768d682ae933ee7f44a4d2515935d0a49b956ff9bb4cf7fc7f6b791a6` |
| `BiosImageProc.dll` | 240584 | `e9d696f8cd712bcefe6fa2bff19bdfed170fc7de02e405700b0f5418fe3d4448` |
| `Ding.wav` | 105886 | `d4d8967f651e91a34258e53b3478142f73e275520e555a58b52fee3e8589e4f8` |
| `FlsHook.exe` | 36808 | `c34b3dbb25816e280c10013bd1da3221adb62e0d12b271cd77b44e51aa92de90` |
| `FWUpdLcl.exe` | 225560 | `2f98f753ffe3bc5718c040a88f3dc87e63b527dd41b9c83a3105caff16c2f203` |
| `H2OFFT-W.exe` | 759296 | `a62316c113c92f88a042cf84ed589f8eab1ec9de99e3e2da65ad982a9653103e` |
| `H2OFFT.cat` | 9001 | `66c2ce179a4ab5487490522bfb38788372395703006654c740d35acba58720f2` |
| `H2OFFT.inf` | 4784 | `da97bf6a87496d59eb2a31fffa5df1b19948ebe95a9806bd86ed03ce7a6d92bc` |
| `H2OFFT32.sys` | 64328 | `238c3b7f124d111acca45afdd1b49d611fa5b0a8f89f008c19ff664d47cbb4c0` |
| `H2OFFT64.sys` | 76616 | `b07b553dd97d3daa2fb291b7145f541572592721adbac3b68f49a7ff242b5059` |
| `mfc90u.dll` | 1162744 | `e30aabb518361fbeaf8068ffc786845ee84abbf1f71ae7d2733a11286531595a` |
| `Microsoft.VC90.CRT.manifest` | 524 | `9e0220511d4ebdb014cc17ecb8319d57e3b0fea09681a80d8084aa8647196582` |
| `Microsoft.VC90.MFC.manifest` | 548 | `f7205c5c0a629d0cc60e30e288e339f08616be67b55757d4a403a2b54e23922b` |
| `msvcp90.dll` | 568832 | `4f7ed27b532888ce72b96e52952073eab2354160d1156924489054b7fa9b0b1a` |
| `msvcr90.dll` | 655872 | `ed0170d3de86da33e02bfa1605eec8ff6010583481b1c530843867c1939d2185` |
| `platform.ini` | 56348 | `4b2e58817c56376867e0f21c674446691e1767948e58c0053dfa1da9edbcac52` |
| `WDFInst.exe` | 246272 | `e36764851124ee882fcdf2bd9405c7086ecee74fb7628a42bcaee758477251e2` |

Use `Get-FileHash` on the extracted files and compare every entry. Preserve the complete original bundle. Do not run an EXE to obtain a version or verify a hash. File properties can show versions without execution.

The investigated installer was signed by Lenovo. H2OFFT-W.exe 6.28 was unsigned inside that signed container; H2OFFT64.sys 2.0.0.1 and the catalogue had valid signatures. Signature trust and revocation should be checked independently on the machine doing the download.
