# Mirroring VulnHash evidence data

An independent mirror preserves complete batch manifests even if the primary
GitHub repository or VulnHash service becomes unavailable.

## Initial mirror

```shell
git clone --mirror https://github.com/clevcode/vulnhash-data.git
git --git-dir=vulnhash-data.git fsck --full
```

Keep the mirrored Git object database on storage controlled independently of
VulnHash and ClevCode. Record the fetched `main` commit ID after each update.

## Updating without silently accepting rewrites

Fetch into a temporary namespace first:

```shell
git --git-dir=vulnhash-data.git fetch origin \
  refs/heads/main:refs/remotes/audit/main-next
git --git-dir=vulnhash-data.git merge-base --is-ancestor \
  refs/heads/main refs/remotes/audit/main-next
git --git-dir=vulnhash-data.git update-ref refs/heads/main \
  refs/remotes/audit/main-next
```

The `merge-base --is-ancestor` command must succeed. Failure means the public
history was rewritten; preserve both histories and treat that as an incident.
Do not use a pruning mirror job that would automatically discard old objects.

## Validating all manifests

Check out or clone the mirror, then run:

```shell
find batches -type f -name '*.json' -print0 \
  | xargs -0 -n1 python3 verifier/verify.py
```

Offline validation rebuilds every Merkle root. Use `--rpc-url` when a fresh,
independent Base-state check is also required.
