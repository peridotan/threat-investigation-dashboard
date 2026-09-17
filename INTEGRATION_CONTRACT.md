# Threat Investigation Integration Contract v1.0

## Entity deep links

v1.0 keeps the stable `entity` query parameter introduced in v0.8.0 for sibling-tool navigation.

Supported investigation targets:

```text
?entity=actor:G0032
?entity=software:S1242
?entity=technique:T1059.001
?entity=platform:ESXi
```

Accepted actor aliases for the type prefix include `actor`, `threat-actor`, and `group`.
Software accepts `software`, `malware`, or `tool`.
Technique accepts `technique` or `technology`.

Campaign can be addressed as:

```text
?entity=campaign:C0001
```

In v1.0, Campaign deep links open the Campaign Profile / Explorer context. Campaign is not a STEP 3 Investigation Result target.

## Optional investigation context

A sibling tool may optionally set:

```text
&lens=general
&overlay=none
```

Valid lens values:

```text
general
identity
internet
virtualization
server
cloud
```

Valid overlay values:

```text
none
all
identity
internet
virtualization
server
cloud
custom
```

## Current Intelligence navigation context

A source such as Security Intelligence Library may attach navigation context:

```text
?entity=software:S1242
&from=security-intelligence-library
&context=2026-09-qilin-esxi
&contextTitle=Qilin%20activity%20involving%20ESXi
```

Threat Investigation displays this as **INTELLIGENCE CONTEXT**.

Important boundary:

> `from`, `context`, and `contextTitle` are navigation metadata only. They do not create an ATT&CK relationship or change source-recorded evidence.

## Example

```text
../threat-investigation-dashboard/?entity=software:S1242&from=security-intelligence-library&context=2026-09-qilin-esxi
```

The target is resolved to Qilin and the user still explicitly starts the investigation. Deep linking does not auto-run STEP 3.

## Legacy compatibility

The existing Explorer parameters remain supported:

```text
?view=actors&q=...&focus=G0032&tactic=...&platform=...
```

New integrations should prefer `entity=` when the target entity is already known.

## Suite v1.0 alignment

The canonical cross-tool contract is maintained in:

`peridotan/security-intelligence-library/SUITE_INTEGRATION_CONTRACT.md`

This document defines Threat Investigation-specific behavior and remains compatible with that Suite contract.

## Context collection parameters

Threat Investigation accepts repeated Suite context parameters in addition to the primary `entity` target.

### Actor context

```text
?actor=G1057
&actor=G0032
```

Actor values represent navigation or investigation context.

When one Actor is explicitly selected as the primary target, the source may also provide:

```text
?entity=actor:G1057
```

### Technique context

```text
?technique=T1078
&technique=T1098.005
&technique=T1566.004
```

When one unambiguous Technique is the primary target, the source may also provide:

```text
?entity=technique:T1190
```

When multiple Techniques are provided without an explicit `entity`, Threat Investigation presents them as selectable context and does not arbitrarily choose one.

## Evidence boundary

Suite context is not new ATT&CK evidence.

In particular:

- Actor context does not create Actor-to-CVE evidence.
- Technique context does not create a new ATT&CK relationship.
- `from`, `context`, and `contextTitle` remain navigation metadata.
- Deep linking may preselect an investigation target but does not auto-create source-recorded evidence.
