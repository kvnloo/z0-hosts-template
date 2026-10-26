# z0-hosts-template

A template for your **private** per-host config repo for the Zer0 stack
(`.files`, `dash`, `z0intelligence`, `z0evals`, the `z0` hub onboarding).

The public Zer0 repos hold code and neutral defaults only. Values that belong to one
machine (absolute paths, non-default port assignments, device serials, which host runs
what) live in your private copy of this repo. The tools read it at runtime.

## Make your private copy

A GitHub fork of a public repo cannot be private, so use the template instead:

```sh
gh repo create <you>/z0-hosts --private --template kvnloo/z0-hosts-template
gh repo clone <you>/z0-hosts ~/.config/z0-hosts
```

Or, on GitHub, click **Use this template**, then choose **Private**.

Then add a directory for each machine:

```sh
cd ~/.config/z0-hosts
cp -r hosts/example-host hosts/<host_id>     # for example: hosts/desktop, hosts/laptop
$EDITOR hosts/<host_id>/*.toml
python3 scripts/validate.py                  # must print "0 problem(s)"
git add hosts/<host_id> && git commit -m "add <host_id>" && git push
```

You can delete `hosts/example-host` in your copy.

## Where the tools read it

| What | Value |
|---|---|
| Root | `$Z0_HOSTS_DIR`, default `~/.config/z0-hosts` |
| Host directory | `hosts/<host_id>/` |
| `host_id` | `$Z0_HOST_ID`; else the `hosts/*/host.toml` whose `match_hostnames` holds the Tailscale `Self.HostName` or the OS hostname; else none |
| Component file | `hosts/<host_id>/<component>.toml` |

| Component file | Read by |
|---|---|
| `host.toml` | all readers: `match_hostnames`, and `fleet_host` (the `.files` `fleet.toml` host key) |
| `files.toml` | `kvnloo/.files` `scripts/host_overlay.py` (storage roots, service ports, k3s roles) |
| `devices.toml` | `.files` fleet scripts: nodes and phones (peer hostname, role, ssh port, serial) |
| `dash.toml` | `kvnloo/dash` bridge |
| `z0int.toml` | `kvnloo/z0intelligence` |
| `z0evals.toml` | `kvnloo/z0evals` |
| `onboard.toml` | `kvnloo/z0` hub onboarding |

Every key is optional. When a file or a key is absent, the tool uses its neutral default.
When a feature has no safe default, the tool disables that feature and tells you why.
Precedence for each value: explicit environment variable, then this overlay, then the default.

`schema/host.schema.json` lists every key. Every object in it is closed, so a typo fails
validation. `lib/z0_hosts.py` is a stdlib reference reader that consumer repos may vendor.

## Rules: what never goes in here, not even in a private copy

- **No tailnet addresses** (IPv4 `100.64.0.0/10` and the Tailscale IPv6 ULA range) and **no tailnet names**
  (`*.ts.net`, `tail<hex>`). Tools discover them at runtime with `tailscale ip -4` and
  `tailscale status --json`. Store the peer's short machine name (`peer_hostname`) instead.
- **No address keys.** A key named like `ip`, `addr`, `tailnet`, `dns_name` or `fqdn` fails
  validation, at any depth.
- **No secrets.** No tokens, API keys, passwords or private keys. Store a path to a key file
  (`key_file`) if a tool needs one; keep the file itself in your secret store.

`scripts/validate.py` enforces these rules. It also takes `--denylist FILE` (one literal per
line) so you can prove that a public tree holds none of your private values:

```sh
python3 scripts/validate.py /path/to/public/repo --denylist ~/.config/z0-hosts-denylist.txt
```

The `guard` workflow runs `validate.py` and a pinned, checksum-verified `gitleaks` on every
push, in this template and in every private copy.

## Updating your copy from the template

```sh
git remote add template https://github.com/kvnloo/z0-hosts-template.git
git fetch template && git merge --allow-unrelated-histories template/main
```

Your `hosts/` directories do not conflict with the template, which only ships `hosts/example-host`.

## License

MIT. See `LICENSE`.
