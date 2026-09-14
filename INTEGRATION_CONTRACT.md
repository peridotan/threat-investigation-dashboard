# Threat Investigation Integration Contract v0.8

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
