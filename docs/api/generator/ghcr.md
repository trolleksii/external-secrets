GHCRAccessToken creates a Github App Installation Access token that can be used to pull OCI images from GHCR. Github App must have following permissions to allow pulling images:

```
metadata: read-only
packages: read-only
```

You must specify the `spec.appID`, `spec.installationID`.

## Output Keys and Values

| Key        | Description                                                               |
| ---------- | ------------------------------------------------------------------------- |
| username   | username for the `docker login` command.                                  |
| password   | password for the `docker login` command.                                  |
| expiry     | time when token expires in UNIX time (seconds since January 1, 1970 UTC). |

## Authentication

### Private Key

Use `spec.privateKeySecretRef` to point to a Kubernetes Secret that has the Github Application Private Key.


## Example Manifest

```yaml
{% include 'generator-ghcr.yaml' %}
```

Example `ExternalSecret` that references the GHCRAccessToken generator:
```yaml
{% include 'generator-ghcr-example.yaml' %}
```
