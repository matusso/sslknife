# Releasing

Releases are built by [GoReleaser](https://goreleaser.com) in the
[`release`](../.github/workflows/release.yml) GitHub Actions workflow. One
release produces:

- binaries for linux/darwin (amd64, arm64) and windows/amd64, with SBOMs
- `.deb` and `.rpm` packages for linux amd64/arm64 (binary in `/usr/bin`,
  bash/zsh/fish completions), smoke-tested on Ubuntu and UBI 9 after the
  release is published
- `checksums.txt`, signed keylessly with Sigstore cosign
- multi-arch Docker images `ghcr.io/matusso/sslknife:<version>` and `:latest`
- an updated Homebrew formula in
  [`matusso/homebrew-tap`](https://github.com/matusso/homebrew-tap)

## Versioning

Versions follow [semantic versioning](https://semver.org) and are git tags
of the form `vMAJOR.MINOR.PATCH`. The binary gets its version from the tag
(`sslknife version`).

There are two ways to release:

1. **From GitHub Actions** (preferred). Open *Actions → release → Run
   workflow* on `main` and pick `patch`, `minor` or `major`. The workflow
   takes the highest existing `v*.*.*` tag, increments it, pushes the new tag
   and releases it in the same run.
2. **By pushing a tag** yourself:

   ```sh
   git tag -a v0.2.0 -m v0.2.0
   git push origin v0.2.0
   ```

The changelog is generated from commit messages since the previous tag;
`docs:` and `test:` commits are left out.

## Homebrew tap

GoReleaser writes `Formula/sslknife.rb` to `matusso/homebrew-tap` on every
release, so users get new versions with `brew upgrade`:

```sh
brew install matusso/tap/sslknife
brew upgrade sslknife
```

GoReleaser pushes the formula over SSH with a deploy key, so no personal
access token is needed. The release workflow fails early if the key is
missing, instead of silently skipping the formula as it used to.

One-time setup:

1. Create the public repository `matusso/homebrew-tap` with a `main` branch
   (for example with a README).
2. Generate a key pair and add the public half as a deploy key with write
   access, and the private half as the Actions secret
   `HOMEBREW_TAP_DEPLOY_KEY` of `matusso/sslknife`:

   ```sh
   ssh-keygen -t ed25519 -N '' -C sslknife-release -f tap_key
   gh repo deploy-key add tap_key.pub -R matusso/homebrew-tap --allow-write -t sslknife-release
   gh secret set HOMEBREW_TAP_DEPLOY_KEY -R matusso/sslknife < tap_key
   rm tap_key tap_key.pub
   ```

The formula is a regular formula rather than a cask, so the same tap works
on macOS and Linux. GoReleaser marks `brews` as deprecated in favour of
casks; it still works.

## Checking the configuration locally

```sh
go run github.com/goreleaser/goreleaser/v2@latest check
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,docker
# packages land in dist/*.deb and dist/*.rpm
```
