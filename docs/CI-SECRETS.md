# CI Secrets

The release signing workflow relies on the following GitHub Actions secrets. None of the key
material should be committed to the repository.

| Secret name | Description |
| ----------- | ----------- |
| `COSIGN_PRIVATE_KEY` | PEM-encoded private key used by `cosign sign-blob` and `cosign attest-blob` to sign release outputs. Provide the full key content as the secret value. |
| `COSIGN_PASSWORD` | Password protecting the Cosign private key (leave empty only if the key is generated without a password). |
| `COSIGN_PUBLIC_KEY` | PEM-encoded public key paired with the private signing key. Stored as a secret so the workflow can verify signatures before uploading assets. |

Publish the public key outside of CI (for example in documentation or a dedicated release
page) so consumers can verify signatures locally without needing repository access.
