# Security

## Never commit credentials

`credentials.txt` holds real API keys and is listed in `.gitignore`. Only
`credentials.example.txt`, which has blank values, belongs in the repository.

Before you push, check that nothing sensitive is staged:

```bash
git status --ignored            # credentials.txt should be listed under "Ignored files"
git diff --cached | grep -iE "api_key|cloud_id|password" || echo "clean"
```

If you ever commit a key by accident, **revoke it first** (Kibana → Stack Management →
API Keys), then remove it from history. Deleting the file in a later commit is not
enough, because the key stays in git history.

## Use demo clusters only

This project writes synthetic attack data, including real routable IP addresses used as
field values, and its cleanup runs `_delete_by_query` against shared data streams. Only
point it at demo, lab or trial clusters you control. Use a dedicated API key, and revoke
it once the demo is over.

## Reporting a vulnerability

If you find a security issue in this project's code, please open a
[GitHub security advisory](../../security/advisories/new) on this repository rather
than a public issue.

For vulnerabilities in Elastic products themselves, follow Elastic's process at
<https://www.elastic.co/community/security>.
