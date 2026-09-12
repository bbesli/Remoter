Desktop builds of Remoter ${VERSION} for Linux, Windows and macOS.

<!--
  This file is the body of every draft release. `.github/workflows/release.yml`
  substitutes the version token on the first line and nothing else, so
  everything below is text a person reads while deciding whether to trust a
  download. That step fails if the token is gone, rather than publishing notes
  with no version in them.

  Before publishing the draft, replace the "What changed" section with the
  user-facing entries for this version from CHANGELOG.md — written for somebody
  deciding whether to upgrade, not as a list of commit subjects. Leave the rest
  alone: the warnings people hit are the same every release, and an installer
  for a credential manager that triggers an unexplained security prompt is
  indistinguishable from malware to the person looking at it.
-->

## What changed

_Fill this in from CHANGELOG.md before publishing._

## Which file do I want?

| You are on | Download |
|---|---|
| Windows 10 or 11 | `…-setup.exe` — the ordinary installer. `…_x64_en-US.msi` is the same application for people who deploy by MSI. |
| macOS 12 or newer | `…_universal.dmg` — one file for both Apple silicon and Intel |
| Debian, Ubuntu, Mint | `…_amd64.deb` |
| Fedora, RHEL, openSUSE | `….x86_64.rpm` |
| Any other Linux | `….AppImage` — `chmod +x` it and run it |

`SHA256SUMS.txt` lists the SHA-256 of every file above. To check the one you
downloaded, from the directory you downloaded it into:

```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
```

```bash
# macOS — there is no sha256sum; compare this against the line in SHA256SUMS.txt
shasum -a 256 Remoter_*_universal.dmg
```

```powershell
# Windows
Get-FileHash .\Remoter_*_x64-setup.exe -Algorithm SHA256 | Format-List
```

A checksum tells you the download arrived intact. It cannot tell you who built
it — that is what code signing does, and see below for why there is none.

## Your operating system will warn you, and here is exactly what to click

**These builds are not signed.** Remoter has no Authenticode certificate and no
Apple Developer ID, because both cost money annually and this project has no
revenue. That is a real gap, it is
[written down as one](https://github.com/bbesli/Remoter/blob/main/docs/development/build-release.md#signing),
and it is not a decision anyone here is happy with. Until it closes, the
operating system has no way to tell you who produced the file, and it says so in
the strongest terms it has.

### Windows — SmartScreen

1. The browser may say the file "isn't commonly downloaded" and offer to
   discard it. Choose **Keep**.
2. Running the installer shows a blue panel: **"Windows protected your PC"**,
   with only a **Don't run** button visible.
3. Click **More info** — the small link under the message.
4. The publisher line appears as **Unknown publisher**, and a **Run anyway**
   button appears. Click it.

That is the whole of it. SmartScreen is telling you it has not seen this file
signed by a certificate it recognises, which is accurate.

**Windows 10 only:** Remoter needs the Microsoft Edge WebView2 runtime. It is
part of Windows 11. On Windows 10 it may be absent, and the installer downloads
and installs it for you — so the machine needs to be online during
installation, and that part of the install is a substantial download rather than
an instant one. If the machine is offline, install
[WebView2 Evergreen](https://developer.microsoft.com/microsoft-edge/webview2/)
first and then run the Remoter installer.

### macOS — Gatekeeper

Open the `.dmg` and drag Remoter to Applications as usual. The first launch is
the one that is blocked.

**On macOS 15 (Sequoia) and newer:**

1. Double-click Remoter. A dialog says macOS "could not verify" that Remoter is
   free of malware. Click **Done**.
2. Open **System Settings → Privacy & Security** and scroll to the bottom of
   the page.
3. A line reads **"Remoter was blocked to protect your Mac."** Click
   **Open Anyway** beside it.
4. Authenticate with Touch ID or your password, then click **Open Anyway** once
   more in the confirmation.

**On macOS 12, 13 and 14:** Control-click (or right-click) Remoter in
Applications, choose **Open**, and click **Open** in the dialog that appears.
Double-clicking will not offer that choice — the Control-click is what matters.

Either way it is a one-time decision; afterwards Remoter launches normally.

### Linux

No warning, because Linux has no equivalent gatekeeper. Install the `.deb` or
`.rpm` with your package manager, or mark the AppImage executable:

```bash
chmod +x Remoter_*.AppImage && ./Remoter_*.AppImage
```

## Before you put real credentials in it

Remoter is alpha. The vault format has not had an independent cryptographic
review — that is a v1.0 release gate, recorded in
[the roadmap](https://github.com/bbesli/Remoter/blob/main/docs/roadmap.md).
Keep another copy of anything you cannot afford to lose.

Remoter does not update itself and does not report anything about you. The only
request it ever makes that you did not ask for is an opt-in, off-by-default
check of this release list — see
[Updates](https://github.com/bbesli/Remoter/blob/main/docs/development/build-release.md#updates).
