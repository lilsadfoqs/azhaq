# Detection templates

`templates.json.gz` is compiled from the MIT-licensed nuclei-templates
(`http/technologies` and `http/exposed-panels`); see `LICENSE.md`.

- Release tag: v10.5.2
- Commit: 5442582a875f96887bfe403c6de562de460897e7
- Compiled: 2367 requests from 2366 templates
- Skipped: 402
- Extractors dropped (unsupported type or part, only the version is lost): 29

## Skipped by reason

- payloads: 240
- raw request: 40
- flow: 30
- request body: 22
- status 3xx needs an unfollowed redirect: 14
- custom request headers: 11
- internal extractor: 10
- dsl function compare_versions: 8
- path uses variables: 6
- dsl identifier version: 5
- matcher uses variables: 3
- no matchers: 3
- dsl identifier status_code_1: 2
- dsl identifier body_1: 1
- dsl identifier http_body: 1
- dsl identifier status_code_2: 1
- matcher type xpath: 1
- method POST: 1
- path is not relative to the base URL: 1
- self-contained: 1
- template variables: 1

## Semantics kept and relaxed

- The caller supplies the response, so `redirects`, `host-redirects` and `max-redirects` are ignored;
  templates that need an unfollowed redirect (`redirects: false`, a 3xx status matcher) are skipped.
- `stop-at-first-match` only limits which paths a scanner requests, so every path is matched on its own.
- Extractors of other types than regex and kval, or on an unknown part, are dropped; the match stays.
- A template with one payload variable, its values written in the template and used only in the paths,
  is its own list of paths. Payloads from a file, several variables, or a variable in a matcher are skipped.
- An extractor gives every match, as nuclei does; the version is the first value shaped like one (`6.1.1`, not `2005-2024`).

## Regenerate

Unpack a nuclei-templates release, then run from the repository root:

```
go run ./scripts/detectgen -src DIR -out internal/detect -tag TAG -commit SHA
```

The output is deterministic: the same release gives the same bytes.
