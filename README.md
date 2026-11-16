# cve-report

cve-report is an LLM-backed tool that writes a [CVE record][cve-schema]
in the JSON 5 format, from the git commits that fix a vulnerability.

Vulnerability details are often still under embargo when the record is
written, so cve-report is designed to run against a **local** model,
which is typically small and unreliable at producing structured output.
The model is therefore never asked to write JSON. It is only asked to:

- write prose (the description and the title), or
- call tools with a few constrained arguments (`write_affected_versions`,
  `write_cvss_score`, `write_severity`, `write_cwe`)

Each tool validates its input against the repository and tells the
model what was wrong, so the model can correct itself. The app then
renders the final record from these findings with a [Jinja][minijinja]
template.

## Usage

### Initialization

```console
$ cve-report init
$ edit ~/.config/cve-report/config.toml
```

The config file defines the model provider for each task. A provider
can be the name of a [declarative provider][declarative-providers] or a
custom provider defined in the `providers/` directory; `init` writes a
sample for [RamaLama][ramalama]. See `.cve-report/` for a sample
configuration. Without a config file, the provider is `none`: nothing
is sent anywhere until you choose a model.

### CWE catalog

Small models tend to pick the right weakness with the wrong number, or
an entry MITRE prohibits for mapping. To check CWEs against the
authoritative definitions, download the official catalog once:

```console
$ curl -LO https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
$ unzip -d ~/.config/cve-report/cwe cwec_latest.xml.zip
```

The newest `cwec_v*.xml` in `~/.config/cve-report/cwe` is used, or the
file or directory given with `--cwe-catalog`. Without a catalog, CWEs
are recorded as the model gives them, with a warning.

### Generating a record

```console
$ cve-report generate CVE-2026-42010 cb1833afd9 \
    -C path/to/gnutls \
    --policy path/to/gnutls/SECURITY.md \
    --tag-format '^(\d+\.\d+\.\d+)$' \
    --repo-url https://gitlab.com/gnutls/gnutls
```

The main arguments are:

- the CVE identifier and the commits fixing the vulnerability
- `-C`: the git repository (default: the current directory)
- `--policy`: the project's security issue handling policy, used to
  rate the severity. `--severity-levels` lists the ratings it defines
  (default: `Critical,High,Medium,Low`)
- `--template`: the record template (default:
  [`templates/default.json.j2`](templates/default.json.j2))
- `--tag-format`: a regular expression matching release tags. Capture
  groups are joined with `.` to form the version, so
  `^gnutls_(\d+)_(\d+)_(\d+)$` maps `gnutls_3_6_12` to `3.6.12`
- `--finder NAME`: a name to credit as a finder, in addition to
  those in `Reported-by:` trailers; may be repeated
- `--var KEY=VALUE`: extra template variables, such as
  `assigner_org_id` or `advisory_url`
- `--cwe-catalog`: the CWE catalog (see above)
- `--schema`: validate the record against a JSON schema, such as
  `CVE_Record_Format_bundled.json` from [cve-schema][cve-schema]

Anything the model would determine can be given on the command line
instead, which skips that step: `--introduced`, `--cvss`, `--severity`,
`--cwe`, `--title`, and `--description`. A `CVSS:3.1/...` vector found in
a commit message is used as is.

See [`examples/gnutls.sh`](examples/gnutls.sh) for a complete
invocation reproducing the upstream part of CVE-2026-42010.

### Writing templates

Templates are rendered with [minijinja][minijinja] with JSON
auto-escaping: `{{ value }}` emits a JSON value (a quoted string, an
object, an array, or `null`), so never put quotes around it. Printing
an undefined variable is an error, while testing one in `{% if %}` is
not. The output is parsed and pretty-printed, so whitespace does not
matter.

Run with `--dump-context` to print every variable available to the
template.

## How it works

cve-report is built using the [goose Development Kit (GDK)][gdk], in
the same architecture as package-rebase-planner. A record is
produced in up to five agent runs. Each run has a narrow goal, because a
small model loses track of a long checklist:

1. **affected**: find the commit that introduced the flaw. The opening
   message already contains the fix and a blame of the lines it touched.
   The model is warned that the last change is not always the
   introduction. The app maps the commit to the first release containing
   it, and maps the fix to the first release containing that. If the
   fix has not been released, the range ends at the latest release
   before it.
2. **score**: record the CVSS v3.1 base metrics (the app computes the
   score, severity, and vector string) and the CWE. The CVSS metrics
   follow the [CVSS v3.1 specification][cvss] alone: each parameter of
   `write_cvss_score` carries the specification's definition of the
   metric and its values, as shown in [FIRST's calculator][cvss-calc],
   and the instructions add the rules of the User Guide, such as scoring
   a library for the reasonable worst-case use. The security policy is
   not shown in this run. With a CWE catalog, the model looks up entries
   with `search_cwe` and `read_cwe` instead of recalling numbers, and
   `write_cwe` follows MITRE's mapping guidance
   (`Mapping_Notes/Usage`):
   - an ID that does not exist, or whose name differs from the one the
     model gave, is rejected, naming the entry the name belongs to
   - a `Prohibited` entry (deprecated, a grouping, a view) is rejected
   - a `Discouraged` entry (e.g. CWE-20, CWE-119) is rejected once with
     MITRE's suggested alternatives, and accepted if the model insists
   - an `Allowed-with-Review` entry is accepted, listing more specific
     entries the model may switch to
   - the name recorded is always the catalog's
3. **rate**: record the severity rating under the policy given with
   `--policy`. The CVSS score is not shown in this run, so that a
   project's own scale is not pulled towards CVSS.
4. **describe**: write the description, as prose.
5. **title**: write the title, as prose.

Facts that git already records are taken from the commits directly:
credits from `Reported-by:`, issue numbers and advisory identifiers from
`Fixes:`/`Closes:`/`Resolves:`, and the public date from the release tag.

To keep a small model on track:

- `finish` is refused while a required `write_*` tool has not been
  called, and a model that stops with prose is reminded to call it
- tool arguments are parsed leniently (`network`, `N` and `NETWORK` are
  all accepted), and errors list the valid choices
- identical tool calls are refused after the third time
- the model is warned as its turn limit approaches
- reasoning blocks (`<think>`), markdown, and labels are stripped from
  the prose

If a run still fails, the record is written without that finding, and a
warning names the command-line option to supply it by hand.

### Tools

- `read_commit`, `read_file`: read git objects
- `blame`: show the commit that last changed each line, by default just
  before the fix
- `search_history`: list commits that added or removed a code snippet
  (`git log -S`)
- `find_release`: find the first release containing a commit
- `search_cwe`, `read_cwe`: look up the CWE catalog
- `write_affected_versions`, `write_cvss_score`, `write_severity`,
  `write_cwe`: record a finding
- `finish`: finish the task, with a summary in prose

## License

MIT

The CVSS v3.1 help text, in the doc comments of the metrics in
`src/cvss.rs`, is copyright FIRST.ORG, Inc., under the BSD 3-clause
license in [`LICENSE-FIRST`](LICENSE-FIRST). As that text is compiled
into the binary, include `LICENSE-FIRST` with binary distributions.

[cve-schema]: https://github.com/CVEProject/cve-schema
[cvss]: https://www.first.org/cvss/v3.1/specification-document
[cvss-calc]: https://www.first.org/cvss/calculator/3.1
[minijinja]: https://github.com/mitsuhiko/minijinja
[declarative-providers]: https://github.com/aaif-goose/goose/tree/main/crates/goose-providers#declarative-providers
[ramalama]: https://ramalama.ai
[gdk]: https://goose-docs.ai/docs/gdk/
