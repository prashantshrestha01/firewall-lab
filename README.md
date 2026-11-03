# firewall-lab

A UFW rule builder and dry-run simulator. You write firewall rules in a
plain-text file, feed it sample traffic, and it tells you — packet by
packet — which rule matched and whether the packet was allowed or denied,
including what the default policy does when nothing matches. It also
prints the equivalent `ufw` commands as text, so you can review them
before anything ever touches a real firewall.

Default mode is **dry-run / simulate only**. This tool does not change
the host firewall unless you explicitly pass `--apply` (see below), and
even then it refuses unless you also pass the long confirmation flag.

## What it does

- Parses a simple rules file: `allow` / `deny`, direction `in` / `out`,
  protocol `tcp` / `udp` / `any`, a single port, a port range
  (`8000-8100`), or `any`, and a source of `any` or an IP / CIDR block
  (e.g. `192.168.1.0/24`).
- Evaluates sample traffic tuples (source IP, destination port,
  protocol, direction) against the rules, first match wins, and reports
  the matching rule or the default policy that decided the outcome.
- Generates the equivalent `ufw` commands as reviewable text.
- Default policies are configurable in the rules file
  (`default-policy in deny`, `default-policy out allow`); without them
  the built-ins are deny-in / allow-out, the usual UFW-style setup.

## Quick start

```bash
# Requires Python 3.10+, no third-party packages.
python3 cli.py --rules examples/rules.txt --traffic examples/traffic.txt
```

Expected output (abridged):

```
Loaded 7 rule(s); default in=deny, out=allow

203.0.113.5 -> port 22/tcp in: ALLOW (matched rule: allow in tcp 22 from any)
203.0.113.5 -> port 23/tcp in: DENY (matched rule: deny in tcp 23 from any)
192.168.1.50 -> port 8050/tcp in: ALLOW (matched rule: allow in tcp 8000-8100 from 192.168.1.0/24)
192.168.1.50 -> port 9000/tcp in: DENY (default policy (deny))
```

Add `--show-ufw` to also print the generated commands:

```bash
python3 cli.py --rules examples/rules.txt --traffic examples/traffic.txt --show-ufw
```

```
  ufw allow in from any proto tcp to any port 22
  ufw deny in from any proto tcp to any port 23
  ufw allow in from 192.168.1.0/24 proto tcp to any port 8000:8100
```

## Writing your own rules

`examples/rules.txt` is the template. One rule per line, `#` starts a
comment:

```
default-policy in deny
default-policy out allow

allow in tcp 22 from any
deny in tcp 23 from any
allow in tcp 8000-8100 from 192.168.1.0/24
allow out udp 53 from any
```

Traffic goes in the same style, one packet per line:

```
192.168.1.50 8050 tcp in
203.0.113.5 3389 tcp in
```

## Safe Linux lab notes

- **Use a VM.** Do all real-firewall experiments in a disposable virtual
  machine or a throwaway cloud instance, never on a machine you need to
  reach over SSH.
- **Never lock yourself out of SSH.** A `deny in` rule that fires before
  your `allow in tcp 22` rule, or a default-deny with no SSH allow rule,
  will cut off remote access. In the sample file, SSH (`allow in tcp 22`)
  is deliberately the first rule. Always simulate first, read the
  generated `ufw` commands, and only then apply — with console access
  available as a fallback.
- **Rule order is the whole game.** Rules are evaluated top to bottom
  and the first match wins. The sample traffic shows this: a packet
  from `10.0.0.9` to port 443 is allowed because the `allow 443` rule
  sits above the `deny ... from 10.0.0.0/8` rule. If you want a block
  list to win, put it first.
- **Real apply is opt-in and lab-only.** It requires both flags, and it
  will not run without them:

  ```bash
  # LAB VM ONLY. Never on a host you care about.
  python3 cli.py --apply --i-understand-this-changes-the-firewall
  ```

  The build of this project never ran `--apply`, and the host firewall
  was not changed at any point.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers allow matches, deny matches, default-policy handling
(both directions, plus the built-in defaults), port ranges including
their boundaries, CIDR matching inside and outside a block, first-match
ordering, malformed rules, UFW command rendering, and an end-to-end run
over the sample rules and traffic files.

## What I learned building this

- A firewall is mostly an ordered list with a fallback: getting
  first-match-wins and the default policy right covers most of the
  behaviour, and most misconfigurations are ordering mistakes, not
  syntax mistakes.
- CIDR matching is easy to get subtly wrong by hand, which is why the
  matching uses Python's `ipaddress` module instead of string prefix
  checks — `192.168.1.0/24` must not accidentally match `192.168.10.x`.
- A simulator is worth more than a command generator on its own: seeing
  *which* rule decided a packet (or that the default did) is what turns
  a rules file from a guess into something you can reason about.

## Dependencies

None. Standard library only (see `requirements.txt`, which is
intentionally empty). Python 3.10+ is enough.

## Files

- `firewall_lab.py` — rule parsing, matching, evaluation, UFW rendering
- `cli.py` — command-line front end (dry-run by default)
- `examples/rules.txt` — sample rules
- `examples/traffic.txt` — sample traffic
- `tests/test_firewall_lab.py` — test suite

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
