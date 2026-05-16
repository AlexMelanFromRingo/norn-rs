# Network namespace end-to-end test

This directory holds a script that exercises `nornd` in two real Linux
network namespaces connected by a `veth` pair — the closest thing to a
real deployment that fits in a CI job.

## What it tests

* `nornd` actually creates a TUN device under `CAP_NET_ADMIN`.
* Two daemons complete the v3 PQ-hybrid handshake over a real TCP socket.
* IPv6 `ping6` between the daemons' `200::/7` overlay addresses succeeds —
  that is, real packets flow TUN → session encrypt → TCP → session
  decrypt → TUN → kernel ICMPv6 in both directions.

## Running it locally

```bash
cargo build --release --features tun-support
sudo tests/netns/run.sh
```

Exit code 0 = pass; anything else = fail.  The script captures both
daemons' stderr/stdout into `/tmp/.tmp.XXXX/{a,b}/log`; if the test fails
those logs are printed before exit.

## Why it's not under `cargo test`

The script needs root (or `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`), spawns
external processes via `ip netns exec`, and binds a real port — none of
which fit cleanly inside the cargo test sandbox. It runs as a separate CI
job in a privileged container.

## CI integration

A `netns-e2e` job in `.github/workflows/ci.yml` runs the script inside
`docker run --privileged --cap-add=ALL` on every PR. The job is gated on
Linux (`runs-on: ubuntu-latest`).
