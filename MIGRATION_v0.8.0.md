# v0.8.0 Rename / Migration

## Rename

Old local directory:

```text
threat-actor-intelligence-dashboard
```

New local directory / future repository name:

```text
threat-investigation-dashboard
```

Recommended local migration:

```bash
cd /c/work/git
mv threat-actor-intelligence-dashboard threat-investigation-dashboard
```

Then extract the v0.8.0 update into the renamed directory.

## Local URL

When serving `/c/work/git`:

```bash
cd /c/work/git
python -m http.server 8000
```

open:

```text
http://localhost:8000/threat-investigation-dashboard/
```

## Preserved browser state

The rename does not intentionally change the shared state keys:

```text
peridotan-threat-investigation-v1
peridotan-security-environment-v1
peridotan-environment-views-v1
```

When both old and new paths are served from the same localhost origin, localStorage remains available because storage is origin-scoped rather than path-scoped.

## Data

`data/dashboard.json` does not need to be regenerated for this update.
