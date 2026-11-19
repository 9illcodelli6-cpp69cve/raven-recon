# RAVEN Recon — copyright, licence and notices

**RAVEN Recon** — Copyright © 2026 mahmoud. All rights reserved except as granted below.

This program is free software: you can redistribute it and/or modify it under the terms of
the **GNU Affero General Public License** as published by the Free Software Foundation,
either **version 3** of the License, or (at your option) any later version
(SPDX: `AGPL-3.0-or-later`).

This program is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. You should
have received a copy of it in [`LICENSE`](LICENSE); if not, see <https://www.gnu.org/licenses/>.

**Network use:** if you run a modified version of RAVEN Recon so that other people interact
with it over a network, the AGPL requires you to offer those users the complete
corresponding source code of your version.

## Additional terms (AGPL-3.0 section 7)

These terms are added under section 7 of the licence and apply to every copy and every
modified version:

1. **Attribution (§7b).** You must keep the copyright notice above, this `NOTICE.md` file,
   and the author attribution shown in the application's About / status screens.
2. **No misrepresentation of origin (§7c).** A modified version must be clearly marked as
   modified (for example in its name, its README and its About screen) and must not be
   presented as, or confused with, the official RAVEN Recon or its official releases.
   Repackaged copies (for example "RAVEN PRO", "RAVEN Premium", "cracked" or "unlocked"
   builds) must not claim to originate from this project.
3. **Name and logo (§7e).** This licence grants no rights to use the names "RAVEN Recon",
   "RAVEN-Sec" or the RAVEN logo, except to truthfully describe the origin of the work.

Official releases are published only at `https://github.com/9illcodelli6-cpp69cve/raven-recon/releases`
and carry SHA-256 checksums and GitHub build-provenance attestations
(see [Verify your download](README.md#verify-your-download)).

## Responsible use

RAVEN Recon is a security-testing tool. Use it only on systems you own or are explicitly
authorised to test — see [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md).

## Third-party components and data

RAVEN Recon's own code is covered by the licence above. It uses or can download the
following third-party works, which keep their own licences:

| Component | Used for | Licence |
|---|---|---|
| Python packages (pywebview, textual, aiohttp, numpy, scikit-learn, anthropic, cryptography, …) | runtime | their own (MIT / BSD / Apache-2.0) |
| Qwen2.5-Coder-0.5B-Instruct (downloaded on demand, not in this repo) | local RAVEN-Sec model | Apache-2.0 |
| MITRE CWE / CAPEC / ATT&CK (downloaded on demand) | local knowledge base | MITRE terms of use |
| OWASP Web Security Testing Guide & Cheat Sheets (downloaded on demand) | local knowledge base | CC BY-SA 4.0 |
| PayloadsAllTheThings (downloaded on demand) | local knowledge base | MIT |
| Claude (Anthropic API, optional, your own key) | AI chat and agent | Anthropic's terms; you pay for your own usage |
| Background artwork `web/assets/raven-mask.jpg` (and screenshots that show it) | UI background | **not** covered by the AGPL — rights remain with their owners; replace it if you redistribute and do not hold those rights |

The testing playbooks in `raven/skills/` were written from scratch for RAVEN Recon from public
methodology (OWASP, PortSwigger, MITRE) and are covered by this project's licence.
