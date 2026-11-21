# First GitHub publication

This folder is prepared for publication, but nothing has been uploaded and no
remote repository has been created by the preparation process.

## Suggested repository details

Name: `legion-bios-recovery`

Description:

> Offline BIOS password recovery for Lenovo Legion 5 17ACH6H (GKCN65WW), with HFDM/LSPE validation and an owner-confirmed recovery case.

Topics:

```text
lenovo legion bios uefi firmware insydeh2o python reverse-engineering password-recovery repair right-to-repair
```

Do not advertise this release as a universal unlocker. It includes the narrow
GKCN65WW offline decoder; other models/revisions are unsupported.

## Before uploading

1. Read README, the readback risks, LEGAL and PUBLICATION_DECISION.
2. Run `python -B -m unittest discover -s tests -v` and
   `python -B scripts/audit_publication.py`.
3. The exact files for publication are listed in `PUBLISH_FILES`. Do not upload
   the parent research folder, `private/`, generated reports or ZIP archives of
   the whole working directory.
4. Keep the MIT notice or choose your preferred public attribution. Do not add
   your Windows account name, serial number, password or private email.
5. The owner has explicitly selected inclusion of the original offline decoder.
   Read the updated disclosure scope in PUBLICATION_DECISION. The exact vendor
   EULA and jurisdiction-specific legal permission are not certified by this project.

## Create the repository yourself when ready

On GitHub, select **New repository**, use the name and description above, and
choose Public only after inspecting the exact file list. Do not ask GitHub to
generate a second README, license or ignore file.

For a browser upload, upload only the files in `PUBLISH_FILES`, preserving the
`docs/`, `scripts/` and `tests/` directories. Make sure `.gitignore` is present;
your file picker may hide it. Do not drag the research workspace into GitHub.

Alternatively, in a shell whose current directory is this project, initialize
a separate local repository and stage the explicit inventory:

```powershell
git init
git branch -M main
$publicFiles = Get-Content -LiteralPath ./PUBLISH_FILES
git add -- $publicFiles
git diff --cached --name-only
git diff --cached
python -B scripts/audit_publication.py
```

These commands are instructions only. The preparation process has not run them
in this project. Check that `git rev-parse --show-toplevel` identifies this
folder, not a parent workspace. Review every staged change before making your
first commit. Configure a chosen public or GitHub-provided noreply commit email
if you do not want a personal email in public Git history. Use GitHub's displayed
remote instructions only after that review; no push command is supplied here.

`.gitignore` protects untracked files only. `git add -f`, browser uploads and
release attachments can bypass it. The audit is a useful gate, not a proof that
arbitrary new text is free of private identifiers. It checks the current public
files, not every historical commit. A secret already pushed requires incident
handling; merely deleting it in a later commit is insufficient.
