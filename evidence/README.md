# Evidence Bundles

The FixOps demo previously committed generated `.zip` bundles for APP1–APP4. Because
binary artifacts are not supported by our automation when opening pull requests,
these archives are no longer tracked in git.

To reproduce them locally, run:

```
python -m cli.fixops_ci evidence bundle --tag APP1 --out evidence
python -m cli.fixops_ci evidence bundle --tag APP2 --out evidence
python -m cli.fixops_ci evidence bundle --tag APP3 --out evidence
python -m cli.fixops_ci evidence bundle --tag APP4 --out evidence
```

Each invocation recreates `evidence/bundles/<TAG>_bundle.zip` along with the updated
`MANIFEST.yaml`. The repository `.gitignore` already excludes the generated archives,
so subsequent commits remain text-only.
