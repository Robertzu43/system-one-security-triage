# Credential readiness

Observed locally on 2026-09-18 using presence-only and read-only checks. No secret value, length, prefix, hash, or credential file was read or recorded. No Jev, Terra, or Opus model call was made.

| Requirement | Result | Readiness |
| --- | --- | --- |
| `TYPESAFE_API_KEY` | Not present in the current process environment | Blocked |
| Claude CLI | Claude Code `2.1.277` installed | Ready |
| Claude authentication | `claude auth status` did not report an authenticated session | Blocked |
| Frozen Opus model | No full immutable Opus model ID was exposed by the unauthenticated CLI's read-only help/status surfaces | Blocked |

The moving `opus` alias is intentionally not recorded as a frozen benchmark model. Authentication must be established before repeating read-only model discovery; discovery must not send a prompt or incur a paid model call.

## User actions required

1. Create or rotate the TypeSafe API key in the TypeSafe account interface. Store it in the user's approved secret manager and export `TYPESAFE_API_KEY` into the benchmark shell using the user's preferred persistent shell mechanism. Do not paste it into this repository, a command transcript, or the readiness document.
2. Run `claude auth login` interactively and complete the account sign-in flow.
3. Re-run `claude auth status` to confirm authentication.
4. Use an authenticated, read-only Claude CLI model-listing or metadata surface, if available, to capture the complete immutable Opus model ID. If the CLI still exposes only `opus` or another moving alias, leave model readiness blocked rather than making a model call or guessing an ID.
5. Repeat the presence-only TypeSafe check and update only the yes/no readiness state. Never record the credential itself.

Key rotation, secret-manager storage, persistent shell export, and Claude sign-in are intentionally left to the user.
