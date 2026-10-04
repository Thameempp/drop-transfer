# Releasing drop (Homebrew + WinGet)

A release is one tag. GitHub Actions (`.github/workflows/release.yml`) runs GoReleaser (`.goreleaser.yaml`), which:

1. builds `drop` for macOS, Linux and Windows (amd64 + arm64), with the version stamped in (`drop --version`);
2. publishes a GitHub Release with the archives and `checksums.txt`;
3. updates the **Homebrew** formula in the `Thameempp/homebrew-tap` repository;
4. opens a **WinGet** pull request against `microsoft/winget-pkgs` from your fork.

Users then install with:

```bash
brew install Thameempp/tap/drop     # macOS (and Linux with Homebrew)
winget install Thameempp.Drop       # Windows
```

## One-time setup

### 1. Homebrew tap
1. On GitHub create a **public** repository named exactly `homebrew-tap` under `Thameempp` (empty is fine; add a README).
2. Create a **fine-grained personal access token** with *Contents: Read and write* on `Thameempp/homebrew-tap` only.
3. In `Thameempp/drop-transfer` → Settings → Secrets and variables → Actions, add it as `HOMEBREW_TAP_GITHUB_TOKEN`.

### 2. WinGet
1. Fork <https://github.com/microsoft/winget-pkgs> to `Thameempp/winget-pkgs`.
2. Create a personal access token that can push to that fork and open pull requests (classic token with `public_repo`, or fine-grained with *Contents* and *Pull requests* write on the fork, plus access to open PRs on `microsoft/winget-pkgs`).
3. Add it as the repository secret `WINGET_GITHUB_TOKEN`.
4. The **first** submission is reviewed by humans and by automated checks (Microsoft's validation installs and scans the package), so expect days, and possibly requests for changes. Later versions are usually approved automatically within hours. Until the first PR is merged, `winget install Thameempp.Drop` does not work yet.

If you would rather not automate WinGet at all, delete the `winget:` block from `.goreleaser.yaml` and submit manifests yourself with [`wingetcreate`](https://github.com/microsoft/winget-create).

## Making a release
```bash
# on main, with CI green
git tag v0.2.0
git push origin v0.2.0
```
Watch the *release* workflow in the Actions tab. Tags must look like `vMAJOR.MINOR.PATCH` (add `-rc.1` for a pre-release, which GoReleaser marks as such and the tap/WinGet steps skip).

## Testing the pipeline without publishing
```bash
go run github.com/goreleaser/goreleaser/v2@latest check
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish
ls dist/                   # archives, checksums, generated formula/manifests
```

## Good to know
- The version users see comes from the tag. A local `make build` stamps `git describe` instead.
- The binary is named `drop`. If another tool called `drop` is already on a user's PATH, whichever comes first wins; `brew install` will warn about a conflicting formula of the same name, which is why the documented command is the fully qualified `Thameempp/tap/drop`.
- Windows SmartScreen may warn about an unsigned `drop.exe` downloaded directly. Installing through WinGet avoids most of that; code signing (e.g. via a certificate or Azure Trusted Signing) is a separate, optional step.
- Upgrades: `brew upgrade drop` and `winget upgrade Thameempp.Drop`. The background receiver and clipboard recorder (if installed) record the path of the binary, so after an upgrade run `drop active service install` once (Homebrew's path is stable across upgrades, so this is rarely needed on macOS).
