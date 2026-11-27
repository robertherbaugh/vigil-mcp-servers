# Contributing

Thanks for helping. Bug fixes, new servers, and tighter limits are all welcome.

## Developer Certificate of Origin

Like [Vigil](https://github.com/Vigil-SOC/vigil), this project uses the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO 1.1). Sign off every
commit to certify you wrote it or have the right to submit it under Apache-2.0:

```sh
git commit -s -m "feat(unifi-containment): block a client with a TTL"
```

That adds `Signed-off-by: Your Name <you@example.com>`. Commits without it can't be merged.
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), scoped by
server or package.

## Set up

```sh
uv sync                  # Python 3.12+, every workspace member, dev tools
uv run ruff check && uv run ruff format --check
uv run pytest
```

## Add a server

1. Copy `servers/_template` to `servers/<name>` and rename the package (`pyproject.toml`
   `name`, `[project.scripts]`, `src/vigil_mcp_<name>`) and the Dockerfile's `PACKAGE` and `CMD`.
2. Put every tool in the `EFFECTS` table with its Vigil effect class. Wrap every tool body in
   `guard.call(...)`. No tool takes a free-form command, URL or path (see
   [docs/DESIGN.md](docs/DESIGN.md)).
3. Give every reversible tool an undo tool and a TTL, using the vendor's own expiry where it has
   one.
4. Test the refusals, not only the happy path: a target outside the allow list, one on the deny
   list, a TTL out of bounds, the rate limit, a missing token.
5. Document in the server's README: its tools and classes, the upstream credential it needs and
   the narrowest rights that credential needs, its settings, and its `sources/<name>.md`.
6. Add a CI build for its image (copy the template's job in `.github/workflows/ci.yml`).
7. Move it from "planned" in [docs/ROADMAP.md](docs/ROADMAP.md).

## Examples and privacy

Use `example.com` names and documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) in examples and tests. Never commit a real host name, address, token or key.
