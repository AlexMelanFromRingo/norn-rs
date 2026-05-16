# Packaging / deployment helpers

This directory holds material for running `norn-rs` as a real system service.
The build output (`nornd`, `nornctl`) is the same as `cargo build --release`;
the files here are what a distro packager would ship alongside the binaries.

## Layout

```
contrib/
├── systemd/
│   └── norn.service         # hardened systemd unit
└── man/
    ├── nornd.8              # daemon man page
    └── nornctl.8            # admin client man page
```

## Suggested install layout

```
/usr/local/bin/nornd
/usr/local/bin/nornctl
/usr/local/share/man/man8/nornd.8
/usr/local/share/man/man8/nornctl.8
/lib/systemd/system/norn.service
/etc/norn/norn.toml           (mode 0600, owner norn:norn)
/var/lib/norn/                (state dir if/when needed)
/run/norn/                    (runtime dir, created by systemd)
```

## Minimum install (Ubuntu / Debian)

```bash
# 1. Build
cargo build --release --features tun-support
sudo install -m 755 target/release/nornd   /usr/local/bin/
sudo install -m 755 target/release/nornctl /usr/local/bin/
sudo install -m 644 contrib/man/nornd.8    /usr/local/share/man/man8/
sudo install -m 644 contrib/man/nornctl.8  /usr/local/share/man/man8/

# 2. Service user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/norn norn
sudo install -d -o norn -g norn -m 700 /var/lib/norn
sudo install -d -o root -g norn -m 750 /etc/norn

# 3. Config
sudo -u norn /usr/local/bin/nornd genconfig -o /etc/norn/norn.toml
sudo chown root:norn /etc/norn/norn.toml
sudo chmod 0640 /etc/norn/norn.toml      # root writes, norn reads
# nornd's `load()` actually demands 0600 — adjust to taste; safest is
# `chmod 0600 /etc/norn/norn.toml && chown norn:norn /etc/norn/norn.toml`.

# 4. Service
sudo install -m 644 contrib/systemd/norn.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now norn

# 5. Verify
sudo systemctl status norn
sudo -u norn nornctl -s /run/norn/norn.sock status
```

## Hardening notes baked into the unit

* `User=norn`, no shell, `NoNewPrivileges=true`.
* Only `CAP_NET_ADMIN` (for the TUN device); no other capabilities.
* `ProtectSystem=strict` + `ReadOnlyPaths=/etc/norn` — the daemon cannot
  modify its own config or anything outside the runtime dir.
* `DeviceAllow=/dev/net/tun rw` — the only device node it can touch.
* `MemoryDenyWriteExecute=true`, `LockPersonality=true`,
  `RestrictNamespaces=true` — standard process hardening.
* `SystemCallFilter=@system-service` minus `@privileged @resources`.
* `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.

## Updating

```bash
cargo build --release --features tun-support
sudo systemctl stop norn
sudo install -m 755 target/release/nornd   /usr/local/bin/
sudo install -m 755 target/release/nornctl /usr/local/bin/
sudo systemctl start norn
```

## Bash / Zsh / Fish completions

`nornctl` ships a built-in completion generator. Install with:

```bash
# Bash (system-wide)
nornctl completions bash | sudo tee /usr/share/bash-completion/completions/nornctl >/dev/null

# Zsh (user — make sure ~/.zsh/completions is in $fpath in your .zshrc)
nornctl completions zsh > ~/.zsh/completions/_nornctl

# Fish (user)
nornctl completions fish > ~/.config/fish/completions/nornctl.fish

# PowerShell
nornctl completions powershell > $PROFILE.CurrentUserAllHosts
```

Re-run after every `nornctl` upgrade so completions track new subcommands.
