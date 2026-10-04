# tiny-injection-gate

A tiny prompt injection gate for a tool-using agent, in one TypeScript file.
It puts three guards (none, a keyword filter with a late detector, and a Rule of Two gate) in front of the same tools and runs three emails through them.
The inbox, files and model are mocks. No API key.

## Why it matters

Most agent guardrails read text. Attackers write text.
An encoded payload can walk past a filter, and a detector that fires after the tool runs is a log, not a guard.

The Rule of Two gate never reads the email. It tracks what the session has touched (untrusted input, private data, external actions) and asks a human before a call would combine all three.

## Run it

You need Node.js 18 or newer.

```bash
npm install
npx tsx gate.ts
```

## Example output

This is real output from `npx tsx gate.ts`:

```text
Scenario: plain injection in an email
  no guard        LEAKED  sent: attacker@example.com
  keyword filter  safe    sent: nothing
                  - blocked: filter matched /ignore (all )?previous/i
  rule of two     safe    sent: nothing
                  - asked, human said no: send_email would combine untrusted input + private data + external action

Scenario: encoded injection in an email
  no guard        LEAKED  sent: attacker@example.com
  keyword filter  LEAKED  sent: attacker@example.com
                  - detector flagged run_code AFTER it ran
  rule of two     safe    sent: nothing
                  - asked, human said no: run_code would combine untrusted input + private data + external action

Scenario: legit request that needs all three
  no guard        safe    sent: ben@example.com
  keyword filter  safe    sent: ben@example.com
  rule of two     safe    sent: ben@example.com
                  - asked, human approved send_email

```

The filter catches the plain injection and misses the encoded one. The detector notices only after the data is in the attacker's outbox. The gate stops both, and the legit request still goes through with one approval.

## How it works

```text
Email ──→ context (untrusted)
            ↓
Model ──→ proposes run_code
            ↓
Gate ──→ legs: untrusted + private + external
            ↓
Human ──→ yes or no, before it runs
```

| File | What it does |
| --- | --- |
| `gate.ts` | The whole demo, in the same order as the post |
| `output.txt` | Real output of `npx tsx gate.ts` |
| `package.json` | `tsx`, `typescript` and `@types/node` as dev dependencies |
| `tsconfig.json` | Strict settings for `npx tsc --noEmit` |

Inside `gate.ts`:

- `tools`: each tool carries capabilities (`untrusted`, `private`, `external`). `run_code` carries all three.
- `execute`: a MOCK world. `run_code` is a toy interpreter that understands one program, `send(read(path), to)`. No `eval`.
- `mockModel`: a MOCK model that obeys any instruction in its context, plain or encoded. The worst case, on purpose.
- `keywordFilter`: scans ingested email text, plus a detector that reads the decoded program after `run_code` runs.
- `ruleOfTwo`: asks a human when a call would give the session all three legs.
- `run`: the harness loop. The guard sits between the model's proposal and `execute`.

What is real and what is mocked:

- Everything is mocked. No network. No API key.
- Email addresses, file names and file contents are example inputs.
- The Rule of Two follows Meta's "Agents Rule of Two" (Oct 31, 2025). The three legs follow Simon Willison's "lethal trifecta" (Jun 16, 2025). This is not either one's implementation, and it is not how Manus works.

## Limits

This is a teaching gate.

- The gate is only as honest as the capability tags. A tool that can fetch a URL is an external channel.
- Too many approvals train people to click yes.
- Legs are tracked in memory. A real harness resets them with a fresh session.
- The keyword filter has false positives. Use filters as signals, not as the boundary.
- The gate limits the highest impact outcomes. An injected email can still make a summary wrong.

## Read more

- Dev.to: [One Email Hijacked an AI Agent. Build a Tiny Prompt Injection Gate in TypeScript.](https://dev.to/bobbyhalljr/one-email-hijacked-an-ai-agent-build-a-tiny-prompt-injection-gate-in-typescript-474b)
- Substack: [One Email Hijacked an AI Agent. Build a Tiny Prompt Injection Gate in TypeScript.](https://bobbyhalljr.substack.com/p/one-email-hijacked-an-ai-agent-build)
- Sources: [Salt Labs, Oct 1, 2026](https://salt.security/blog/how-we-hijacked-an-ai-agent-with-a-single-email), [Meta, Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/), [Simon Willison, The lethal trifecta](https://simonwillison.net/2025/jun/16/the-lethal-trifecta/)

## License

MIT. See [LICENSE](LICENSE).
