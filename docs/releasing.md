# Releasing

Releases are built by [GoReleaser](https://goreleaser.com) in the
[`release`](../.github/workflows/release.yml) GitHub Actions workflow. One
release produces:

- binaries for linux/darwin (amd64, arm64) and windows/amd64, with SBOMs
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

One-time setup:

1. Create the public repository `matusso/homebrew-tap` (with a README so it
   has a default branch).
2. Create a fine-grained personal access token limited to that repository,
   with *Contents: read and write*.
3. Add it to `matusso/sslknife` as the Actions secret
   `HOMEBREW_TAP_GITHUB_TOKEN`.

Without the secret the release still runs and only the formula upload is
skipped.

## Checking the configuration locally

```sh
go run github.com/goreleaser/goreleaser/v2@latest check
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,docker
```
