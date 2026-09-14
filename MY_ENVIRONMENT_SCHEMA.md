# Shared My Environment schema v1

`My Environment` is a browser-local environment profile shared by peridotan security dashboards that run under the same web origin.

## Storage key

```text
peridotan-security-environment-v1
```

## Schema

```json
{
  "schema_version": "1.0",
  "updated_at": "2026-09-10T00:00:00.000Z",
  "platforms": ["Windows", "Linux", "ESXi"],
  "products": [
    {"vendor": "VMware", "product": "ESXi"},
    {"vendor": "Microsoft", "product": "Windows"}
  ],
  "technologies": ["PowerShell", "Active Directory", "Entra ID"]
}
```

## Semantics

- `platforms`: broad runtime / operating-system platforms used for direct overlap with ATT&CK Technique / Software platform metadata.
- `products`: vendor/product inventory entries. These are independent of the currently loaded KEV or Emerging vulnerability datasets. `product` may be blank to represent a vendor-level entry.
- `technologies`: user-defined technology names. Threat Actor Intelligence v0.4.x only reports **exact name / alias / ATT&CK ID matches** against related ATT&CK Technique and Software entities. It does not use fuzzy semantic inference.

## Interpretation rules

- Environment overlap is not a risk score.
- No match does not mean the technology or product is safe or unrelated in the real world.
- Product-to-CVE correlation is performed by the Vulnerability Intelligence side when suitable vulnerability mapping is available.
- The profile is stored only in browser `localStorage`; it is not uploaded by the static site.

## Legacy migration

Threat Actor Intelligence v0.4.x can import product entries from the existing Vulnerability Intelligence watchlist keys without deleting those legacy keys.
## Input normalization (v0.4.2)

The schema is unchanged. v0.4.2 adds UI-side normalization for selected common Vendor / Product names.

- Safe alias/casing matches can be normalized automatically when saving.
- A Product that uniquely maps to a different known Vendor is shown as a **candidate correction** and is not rewritten automatically.
- Existing mismatched entries require an explicit user action to apply a correction.
- Unknown Vendor / Product values remain valid free-form inventory entries.
- The built-in canonical list is intentionally small and is not a source of truth for assets, vulnerabilities, support status, or Threat Actor relevance.



## Technology normalization (v0.4.2)

Known display aliases may be canonicalized on load/save (for example, `powershell` to `PowerShell`). The stored schema remains `1.0`; normalization is an input/display aid only and is not an ATT&CK mapping or risk assessment.
