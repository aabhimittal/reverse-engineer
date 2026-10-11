# Legal and ethical ground rules

> This chapter is general information, not legal advice. Laws differ by country; when in doubt,
> ask a lawyer and your employer.

## The short version

- **Analyse what you own or are authorised to analyse.** Malware samples you obtained for
  research, your own products, software under a bug-bounty scope, CTF challenges.
- **Interoperability, security research and education are widely recognised purposes**,
  but the details are jurisdiction-specific.
- **Don't redistribute** proprietary code you extracted, or credentials you found.
- **Report vulnerabilities responsibly**: to the vendor first, with a reasonable disclosure timeline.

## Things to check before you start

| Topic | Why it matters |
|---|---|
| **Licence / EULA** | Many prohibit reverse engineering; enforceability varies. Some laws (e.g. the EU Software Directive's interoperability provisions) limit what contracts can forbid. |
| **Anti-circumvention laws** | The US DMCA §1201 and similar laws restrict bypassing technical protection measures, with specific exemptions (security research, interoperability) that come with conditions. |
| **Computer misuse laws** | Interacting with *someone else's* server (replaying API calls, fuzzing endpoints) can be unauthorised access even if reversing the client was fine. A HAR capture of your own traffic is not permission to probe their API. |
| **Bug bounty scope** | Programs define allowed targets and techniques; stay inside them. |
| **Malware handling** | Keep samples in isolated environments, store them encrypted/zipped with the conventional password `infected`, never execute them on your host. |

## How rex helps you stay safe

- rex **never executes** inputs. Everything is static.
- Secrets found during analysis are **masked** in reports, and are **redacted** before anything
  is sent to an AI provider (`--ai` is always opt-in).
- `rex web har2openapi` works on traffic you already captured; it never sends requests.

## Exercise

Pick a piece of software you use daily and read its licence's reverse-engineering clause.
Would analysing its network protocol for interoperability be permitted where you live?
