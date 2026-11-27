# Registering a server with Vigil

This describes Vigil **v1.2.0**. The authoritative text is upstream: the "Remote MCP sources"
section of [`INTENT.md`](https://github.com/Vigil-SOC/vigil/blob/v1.2.0/INTENT.md) and the Helm
chart's [README](https://github.com/Vigil-SOC/vigil/blob/v1.2.0/infra/helm/vigil/README.md)
("Remote MCP sources in the declared directory"). Check them for the version you run.

## 1. Run the server behind HTTPS

Vigil accepts only an `https` URL for a remote source. Give the server:

- `MCP_TOKEN` (or `MCP_TOKENS_FILE`): the token Vigil will present, at least 32 characters;
- `MCP_ALLOWED_HOSTS`: the host name Vigil uses, e.g. `template-mcp.example.com`;
- its own target and rate-limit settings (see the server's README).

## 2. Declare it as a source

Vigil reads remote MCP sources from `sources/<name>.md` in its **declared intent directory**
(`VIGIL_INTENT_DIR` on the daemon). From upstream `INTENT.md`:

> Each `sources/<name>.md` declares one remote MCP server Vigil reaches over streamable HTTP. The
> file stem is the name: lowercase letters, digits and hyphens, never a catalogue server's name
> or `vigil`. The front matter holds only these keys; the body is for people, including who owns
> the source.

```markdown
---
url: https://template-mcp.example.com/mcp
headers:
  Authorization: "Bearer {{token}}"
credentials: [token]
---

# template-mcp

Owner: the SOC team. Rehearsal-only server; changes nothing outside itself.
Source: https://github.com/robertherbaugh/vigil-mcp-servers/tree/main/servers/_template
```

The credential `token` for a source named `template-mcp` is read as
`SOURCE_TEMPLATE_MCP_TOKEN` ("hyphens as underscores"), from Vigil's encrypted store first, then
the environment. On Helm with the default emptyDir state directory, put it in the Secret named by
`secrets.existingSecret` (or the chart's ExternalSecret).

With the Helm chart, the directory is a ConfigMap mounted on the daemon. A ConfigMap is flat, so
map keys to paths with `items` (from the chart README):

```yaml
daemon:
  extraVolumes:
    - name: intent
      configMap:
        name: vigil-intent
        items:
          - {key: REVISION, path: REVISION}
          - {key: sources-template-mcp.md, path: sources/template-mcp.md}
  extraVolumeMounts:
    - {name: intent, mountPath: /etc/vigil/intent, readOnly: true}
  extraEnv:
    - {name: VIGIL_INTENT_DIR, value: /etc/vigil/intent}
secrets:
  existingSecret: vigil-secrets   # carries SOURCE_TEMPLATE_MCP_TOKEN beside the rest
```

## 3. A person accepts it

A new source, or a change to its URL, headers or credential names, **connects nothing** until a
person holding `integrations.install` accepts it (Settings, or `POST /api/config/sources/accept`).
A removal applies at once. Once accepted, the backend and daemon connect within about ten
seconds, with no restart. Each source gets an Integration Health row, `source-<name>`, that says
why it isn't connected (pending, a missing credential, the client's error).

## 4. A person classifies each tool

An accepted source's tools **start unclassified**: they ask first and are not offered in chat
until a person classifies them. Classify each tool with the class it declares (its `_meta`
entry `io.github.robertherbaugh.vigil-mcp-servers/effect-class`, and the server's
`describe_policy` tool), in Settings, or with the API:

```sh
curl -X PUT "https://vigil.example.com/api/v1/autonomy/tools/<tool-name>" \
  -H "Content-Type: application/json" \
  -d '{"effect_class": "read"}'          # read | read_unverified | reversible | irreversible
```

Classifying an unclassified tool counts as a loosening: it needs a person's `ai_autonomy.write`,
never a service account or API token. A person's classification of a remote server's tool pins
the definition held at that moment. If the server later changes the tool's definition, the
classification is withdrawn and the tool asks first again.

Binding a reversible tool as an act carrier, with its undo tool as the way back, is described in
upstream [`docs/acts.md`](https://github.com/Vigil-SOC/vigil/blob/v1.2.0/docs/acts.md).

## 5. Decide the autonomy, separately

Classification says what a tool *is*; Vigil's autonomy ceiling says what may run without a person.
Both reversible and irreversible autonomy are off by default, and only a person can raise them.
Start every new server with autonomy off, approve its actions by hand, and raise reversible
autonomy for one narrow workflow only once its record supports it.

## 6. Restrict the network

Vigil enforces no egress for a source. Allow the Vigil backend and daemon to reach the server's
port, and nothing else, with a NetworkPolicy or your proxy's allowlist.
