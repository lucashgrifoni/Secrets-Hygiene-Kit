# Output publication and recovery

These additions are unreleased. Published 1.0.0 artifacts retain their original behavior.

`scan check`, `scan normalize` and `report` prepare UTF-8 files in exclusive
temporaries in the destination directory, flush and fsync their content, then
replace the destination. A failure before replacement preserves the previous
file. New files use the temporary file's restrictive permissions; replacement
does not retain the previous inode, owner, ACL or extended attributes. On
Windows, effective access also depends on the destination directory's ACL.

`scan check` renders and stages every requested export before publication.
Staging failure leaves existing exports unchanged. Replacement remains
sequential: if a later replacement fails, earlier files may already be new.
The command returns `2` without a success summary; rerun the entire selection.
An interrupted process also requires operator review before consuming exports.

## Optional completion marker

```console
secguard scan check --input gitleaks.json --json findings.json --sarif findings.sarif --output-manifest outputs.json
secguard scan verify-outputs --manifest outputs.json
```

The marker is a separate `secguard.outputs/v1` document containing `complete`,
the preserved `gate` (`PASS` or `BLOCK`) and each artifact's absolute local path,
UTF-8 byte count and SHA-256 digest. It requires at least one file export and
cannot collide with inputs, policies or any export.

An existing marker remains valid if rendering or staging fails without changing
artifacts. It is removed before the first artifact replacement. The new marker
is published last. A missing marker, missing artifact or changed digest means
the selected set cannot be accepted as complete. Verification exits `0` for a
complete set, including a preserved `BLOCK`; it exits `2` for invalid, missing
or changed content. This command checks file integrity, not policy acceptance,
provenance, authenticity or scanner coverage. Keep the check's original exit
code when using this in CI. Consumers must opt into requiring the marker.

## Failure boundaries

- Existing collision and link guards still apply. They do not isolate paths
  from concurrent changes. Use an operator-controlled output directory and a
  single writer. Another command that edits an artifact makes its old marker
  fail digest verification.
- There is no transaction or automatic rollback across files, directories or
  volumes. Temporary files stay on the destination filesystem; enough space
  for all staged content is required.
- Content fsync and successful replacement do not promise directory durability
  after power loss or atomic rename behavior on every network filesystem. The
  supported runtime must be validated on the filesystem actually used.
- Handled exceptions and ordinary interrupts clean up staged temporaries.
  A forced kill can leave `.secguard-*.tmp` files. After confirming that no
  writer is running, identify the abandoned files before removing them. They
  are never completion evidence and are never reused on retry.
- A completion marker can contain sensitive local directory names. Review it
  before sharing; metadata minimization does not rewrite filesystem identity.

The [Python replace](https://docs.python.org/3.12/library/os.html#os.replace),
[fsync](https://docs.python.org/3.12/library/os.html#os.fsync) and
[temporary-file](https://docs.python.org/3.12/library/tempfile.html#tempfile.NamedTemporaryFile)
contracts describe the underlying operations. These are per-file guarantees.
