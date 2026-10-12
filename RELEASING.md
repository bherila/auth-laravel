# Releasing

Follow the release-docs and signed-tag sequence used for v0.24.0 and v0.24.1.
Use the version's CHANGELOG section for notes, as v0.24.1 did. Release only merged
code whose CI passes.

## Choose the version and write upgrade notes

- Use a patch for bug fixes and additive changes, including new optional migrations.
  Use a minor version for contract changes or new required adoption steps.
- Every release involving a migration explains how an application copies or publishes
  it, then lets its reviewed deployment run it. A package update does not run migrations.
  If correcting a migration already recorded as run, explain the new application migration
  needed to apply the correction; republishing alone does not rerun it.
- Upgrade identity providers before applications for a contract change. Acceptance by
  the validator is insufficient: verify that the identity provider's confirmation UI
  shows the new fields before an application emits them.
- A change to cascade rules changes the revision. Include the cascade-rules version
  in the revision so a confirmation made under the old rules is refused.

## Release

1. Open a release-docs PR changing `## Unreleased` in `CHANGELOG.md` to
   `## vX.Y.Z - YYYY-MM-DD`, using the UTC release date. Check the upgrade notes.
   Squash-merge on green CI with `--delete-branch`.
2. Pull `main` and confirm its HEAD is that PR's merge commit, with a clean checkout.
   Create the signed annotated tag on that commit, verify it, and push:

   ```sh
   git switch main
   git pull --ff-only origin main
   git tag -s vX.Y.Z -m vX.Y.Z
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```

   Stop if signature verification fails. Never move or reuse a published tag.
3. Extract that version's CHANGELOG section and publish it as the release notes:

   ```sh
   tag=vX.Y.Z
   awk -v tag="$tag" '
     /^## / { if (found) exit; found = ($2 == tag); next }
     found { print }
   ' CHANGELOG.md > /tmp/auth-laravel-release-notes.md
   grep -q '[^[:space:]]' /tmp/auth-laravel-release-notes.md
   gh release create "$tag" --verify-tag --title "$tag" \
     --notes-file /tmp/auth-laravel-release-notes.md
   ```

   The tag's Release workflow also verifies the signature, creates a release using
   the same section, and notifies Packagist. If it created the release first,
   inspect `gh release view "$tag"` and use `gh release edit "$tag" --notes-file
   /tmp/auth-laravel-release-notes.md` if necessary. Confirm the workflow succeeds.
4. Confirm the exact version and merge commit in
   `https://repo.packagist.org/p2/bherila/auth-laravel.json`:

   ```sh
   curl -fsSL https://repo.packagist.org/p2/bherila/auth-laravel.json |
     jq --arg tag "$tag" '.packages["bherila/auth-laravel"][] |
       select(.version == $tag) | {version, reference: .source.reference}'
   ```

   No matching entry means publication is not confirmed. Wait for indexing and
   verify again; do not tag another commit to force an update.
