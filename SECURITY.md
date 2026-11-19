# Security policy

## Reporting a vulnerability in RAVEN Recon

Please **do not open a public issue** for security problems in RAVEN Recon itself (for
example a way around the scope check, the approval gate, the sandbox, or the local API
token). Report them privately through GitHub:
**Security → Report a vulnerability** on
`https://github.com/9illcodelli6-cpp69cve/raven-recon` (private vulnerability reporting).

Include the version, your OS, steps to reproduce and the impact. You will get an answer
within 7 days; fixes are released as soon as possible and credited to you unless you prefer
otherwise.

## Supported versions

Only the latest release receives security fixes.

## Verify what you download

Official builds are published only on the project's GitHub Releases page. Every release
contains `SHA256SUMS.txt` and a GitHub build-provenance attestation that proves the file was
built by this repository's workflow from a tagged commit:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing          # Linux
gh attestation verify <downloaded-file> --repo 9illcodelli6-cpp69cve/raven-recon
```

On Windows (PowerShell): `Get-FileHash .\RAVEN-Recon-windows-x64.zip -Algorithm SHA256`
and compare with `SHA256SUMS.txt`.

Builds from anywhere else (other repositories, file-sharing sites, "PRO"/"cracked"
versions) are **not** official and may contain malware.

## Reporting misuse

If you see RAVEN Recon being used to attack systems without authorisation, report it to the
affected organisation and to the platform hosting the activity. This project does not
support or condone unauthorised testing (see `RESPONSIBLE_USE.md`).
