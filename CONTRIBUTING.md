# Contributing

Issues and pull requests are welcome, especially new attack chapters, more log sources,
and prompts that work well in the AI walkthrough.

## Ground rules

- **Keep the entity model consistent.** New events should reuse the hosts, users,
  subnets and attacker IPs in [docs/ENTITY_MODEL.md](docs/ENTITY_MODEL.md). That
  continuity is what lets Attack Discovery and the AI agent correlate across sources.
- **Tag everything.** Demo-log events must carry `tags: ["elastic-security-demo-data"]`,
  and simulator events the `elastic-security-sample-data` marker, so cleanup and the
  detection rules keep working.
- **Hidden threats stay hidden.** The Quiet Insider and the Linux compromise are
  intentionally left without baseline rules. Don't add rules for them to
  `docs/DETECTION_RULES.md`, because closing that gap is part of the walkthrough.
- **No secrets, no real customer data.**
- **Keep `simulator/` close to upstream.** Changes there should be limited, so it stays
  easy to compare with [elastic/agent-skills](https://github.com/elastic/agent-skills).
  Describe any change in the file's modification notice and in `NOTICE`.

## Before opening a pull request

```bash
npm install
npm test     # syntax-checks every script and runs the log generator as a smoke test
```

If you can, also run `node run.js` against a demo cluster and confirm that the nine
baseline rules still alert after a manual run (README, Section 8).
