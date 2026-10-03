# agentbus

Five small primitives for agents that run unattended. No dependencies, Python 3.9+, MIT.

Each one exists because something went wrong in a fleet of long-running agents that has
been in daily use since May 2026. They are not a framework and they do not want to be one.

```bash
pip install git+https://github.com/tomnexttech/agentbus   # not on PyPI: "agentbus" there is an unrelated project
# or just copy the five module files; they have no dependencies
```

---

## `LoopbackGuard` — four locks for a localhost endpoint that can run code

Start here if you have an agent listening on 127.0.0.1. This one is a security fix.

You have a small HTTP server on loopback so your dashboard can talk to your agent. One
route starts a coding assistant with file-write and shell permissions. It's on localhost,
so it's private, and there's no login because who would you log in as?

By default that is remote code execution on your workstation, triggerable by any web page
you happen to have open:

```js
// from any page you visit
fetch("http://127.0.0.1:8000/api/run", {method: "POST", mode: "no-cors", body: "..."})
```

The attacker can't read the response — the same-origin policy holds. They don't need to.
**The side effect still happens.**

The obvious defence is three locks: require a custom header (which forces a CORS preflight
you never answer), check `Sec-Fetch-Site`, and verify `Origin` matches `Host`. That is what
most people write, and it is defeated by DNS rebinding — the attacker's domain resolves to
127.0.0.1, so their page is same-origin *with itself*: the browser honestly reports
`same-origin`, the custom header needs no preflight, and `Origin` matches `Host` perfectly,
both being the attacker's domain.

Every header-based lock agrees the request is fine. It isn't.

The fourth and fifth facts you need: **`Host` must be an IP literal** (rebinding works
through a *name*, so the name always lands in `Host` — this is the only place the two cases
diverge), and **the peer address must be loopback** (every header is a claim; `curl` says
whatever you like, and the moment you bind wider than loopback for a phone or a container,
one line of `curl` from the LAN passes all the header checks).

```python
from agentbus import LoopbackGuard

guard = LoopbackGuard(custom_header="X-Agent")

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        ok, reason = guard.check(self.headers, self.client_address[0])
        if not ok:
            self.log_message("refused: %s", reason)   # log it
            return self.send_error(403)               # don't return it
        ...
```

Don't return the reason to the caller — "wrong header" vs "wrong host" vs "wrong peer" is a
free map of your defences. `guard.wrap_handler(H)` applies it to the mutating verbs and
leaves `GET` alone, so a phone on the LAN can still load a read-only panel.

### See it happen

```bash
python3 examples/rce_demo.py
```

Binds a real server to an ephemeral loopback port, fires real HTTP over real sockets, and
detects whether the "run code" route fired by watching for a canary file — not by trusting
the response. Output:

```
── NAIVE GUARD (custom header + Sec-Fetch-Site + Origin == Host) ──
  cross-site POST, no custom header              blocked  ok
  cross-site POST, custom header set             blocked  ok
  old browser: no Sec-Fetch, foreign Origin      blocked  ok
  DNS rebinding: Host carries a domain name      RAN CODE <-- breach
  LAN peer with perfectly forged headers         RAN CODE <-- breach
  the real dashboard, same-origin over loopback  ran      ok

── LoopbackGuard (all four locks) ──
  ...all six correct...
```

Nothing leaves the machine and nothing binds beyond loopback.

`tests/test_loopback.py` keeps the naive implementation around permanently as a **negative
control** and asserts that it is still defeated. If the control ever starts passing, the
test suite has stopped measuring anything and someone needs to look — a suite with no
failing control is measuring the tests, not the code.

---

## `Bus` — one writer per topic, and expiry you can't quietly ignore

Once you have several agents they start fetching the same things separately, and the same
number appears twice on one screen with two different values.

A shared cache is the obvious fix. It has a subtler failure, and that failure is the shape
of this module. We built one where every payload carried `published_at`, `max_age_s`, and a
`stale` flag. Then the fetchers stopped and nobody noticed for hours, and two separate
consumers displayed the stale payloads anyway — one appended the word "STALE" to the label
and printed the value unchanged, the other had no freshness check at all and rendered a
seven-day-old price stamped with the *current* time.

The flag was present and correct. It was ignored twice, without malice, because **reading a
flag is optional and reading a value is not**.

So the flag stopped being a mechanism and became a shape:

```python
from agentbus import Bus, Topic

bus = Bus("~/.myagents", topics={
    "prices": Topic(writer="fetcher", max_age_s=900, ceiling_s=3600, hard_s=86400,
                    basis="upstream refreshes at most every 5 min; 5 min x 3"),
})

bus.publish("prices", writer="fetcher", payload={"usd_jpy": 147.02})

r = bus.take("prices")        # never raises, whatever is on disk
if r.ok:
    prices = r.value()        # raises if stale / absent / unreadable
else:
    show(r.label())           # "stale - observed 04:12 (7.1 hours ago)"
```

- **The exception fires at extraction, not at read.** Reading is something code does
  incidentally; extracting is something code does *because it depends on the answer*. The
  exception belongs where the dependency is. There is no way to get a stale payload out by
  accident.
- **The one escape hatch is greppable.** `r.stale_ok("shown beside the word stale on a
  courtesy panel")` returns the value and demands a real sentence. `grep -rn 'stale_ok('`
  should return a list a maintainer can read in one sitting. If it doesn't, the discipline
  already failed and no further API design saves it.
- **Expiry needs a stated basis.** `Topic(basis=...)` is required. Going past `ceiling_s`
  needs `extend_why=`; `hard_s` can't be bought at any price. "Effectively infinite" becomes
  something the machine rejects rather than something a tired human types.
- **Missing ≠ broken.** `absent`, `unreadable`, `unwired` and `stale` are four states with
  four exceptions. "No data" is often normal; "I can't read the data" is an incident. Collapse
  them into a falsy value and the incident never surfaces.
- **One writer per topic**, declared up front. A second writer is refused unless you pass
  `force=True` on purpose.

A serviceable default for `max_age_s`: *the shortest interval at which the value could
genuinely change, times three.* Three consecutive misses isn't bad luck, it means the thing
that refreshes has stopped. Times one makes every hiccup an outage; times ten makes an
outage invisible.

The rule underneath all of it: **when the layer is missing, say it is missing — never fill
it with a default.** A default is indistinguishable from a real value one call later.

---

## `AtomicJSON` — the five-step write, in the order that matters

```python
from agentbus import AtomicJSON

store = AtomicJSON("~/.myagents/ledger.json")
store.update(lambda cur: {**(cur or {}), "runs": (cur or {}).get("runs", 0) + 1})
```

```
1. flock       exclusive, on a separate lock file
2. re-read     inside the lock, not before it
3. backup      previous good version aside
4. tmp write   same directory as the target
5. os.replace  atomic swap
```

**Step 2 is the one people skip.** Read → lock → write serialises the *writes* but not the
*decisions*: two processes both read version N, both write N+1, one is gone. The lock must
span the read or it's decoration. `tests/test_bus.py` runs eight processes at one counter;
without the re-read it lands around three.

Step 4 must be the same directory — `os.replace` is only atomic within a filesystem.

The lock file is deliberately *not* the target file: locking the target races with
`os.replace`, which swaps the inode out from under the lock you're holding.

Readers never lock. They see the old complete file or the new complete file, never a
half-written one.

---

## `Tri` — because "I don't know" is not "no"

An audit routine was written to *protect* a shared world: before reclaiming a cell, ask
"is this still the thing I put there?", and if not, release the claim rather than overwrite
something a human built. Careful and correct.

The query had three answers: matches, doesn't match, and *"that region is not loaded"* —
paged out because nobody was standing near it. The code collapsed three into a boolean, the
third became "doesn't match", and one afternoon 953 cells that were merely **unobserved**
were classified as someone else's and released.

Nothing crashed. Nothing was logged. The count in the report looked healthy. The mechanism
built to prevent destruction had become the destruction, wearing a completely normal face.

> When one branch of a decision is destructive, collapsing a three-valued answer into two
> will always push "unknown" toward the dangerous side, and it will do so silently.

```python
from agentbus import Tri, unknown_aborts

@unknown_aborts                       # refuses to run if any arg is Tri.UNKNOWN
def release(cell, still_mine): ...

release("b2", Tri.unknown("region not loaded"))
# UnknownRefused: release: refusing to act on Tri.UNKNOWN (region not loaded).
#                 Resolve the unknown or abort; do not default.
```

`Tri` is not a `bool` and raises `TypeError` if you use it as one — the entire failure mode
is code that treats it as a boolean without noticing. `.otherwise(default)` is the deliberate
flattening, spelled that way so `grep -rn 'otherwise('` finds every one.

---

## `stamp` — timestamps that stay true after the screen stops updating

"3 minutes ago" is true for exactly as long as something keeps redrawing it. The instant the
renderer stalls, that label starts lying in the most dangerous way available: it looks fine.

An absolute time without a *date* is the same lie with a longer fuse. On one audit, 15 of 16
status cards were stamped time-of-day only; a six-week-old value sat there reading as
breakfast.

```python
observed_line(t)   # 'observed 14:22 (5 min ago)'
                   # 'observed 07/11 02:05 (43 days ago)'   past 20 hours
```

Absolute first, so that when the line is truncated, screenshotted, or read aloud, the part
that survives is the part that stays true.

---

## Tests

```bash
python3 -m pytest tests/ -q      # or: python3 tests/test_bus.py
```

30 tests, no dependencies. Two are worth reading rather than running:
`test_negative_control_naive_guard_is_defeated` (asserts a vulnerability, so the suite
stays calibrated) and `test_concurrent_updates_lose_nothing` (eight processes, one counter).

## Scope

These are five module files. Copy them into your project if you'd rather not add a dependency —
that's a legitimate use and the licence permits it.

`agentbus` is the free half of **[Agent Fleet Field Notes](https://tomnexttech.gumroad.com/l/agent-fleet-field-notes)**, a written
account of running a fleet of agents unattended: the retrieval cost ladder, memory layering,
supervision, testing things you can't unit-test, and a ledger of about twenty failures with
the rule each one bought. The code is here for free and stays here. The book is the judgment.

## Licence

MIT. See `LICENSE`.
