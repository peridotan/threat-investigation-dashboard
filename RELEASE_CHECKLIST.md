# v1.0 Release Checklist

## Product / naming

- [ ] UI title is `Threat Investigation`
- [ ] local directory / GitHub repository is `threat-investigation-dashboard`
- [ ] footer / HTML title show `v1.0.0`
- [ ] no active UI still presents the old product name `Threat Actor Intelligence Dashboard`

## Functional smoke tests

- [ ] Qilin (`S1242`) resolves as Software
- [ ] Lazarus (`G0032`) resolves as Threat Actor
- [ ] PowerShell (`T1059.001`) resolves as Technique
- [ ] ESXi resolves as ATT&CK Platform investigation target
- [ ] `panda` remains ambiguous until the user selects a candidate
- [ ] `+N more` expands and `Show less` collapses long relationship lists
- [ ] Profile links and Further Investigation preserve the current entity context
- [ ] `↑ Top` works after scrolling

## Evidence boundary

- [ ] Direct Match and ATT&CK Relationship remain visually / semantically distinct
- [ ] Environment Overlay is marked optional
- [ ] no risk score is shown
- [ ] zero relationships are not described as proof of no real-world relationship
- [ ] Library Navigation Context is not described as ATT&CK evidence
- [ ] Vulnerability navigation does not imply Actor → CVE usage

## Legal / public release

- [ ] `LICENSE` exists
- [ ] `license.html` opens in browser without downloading
- [ ] `COPYRIGHT.md` exists
- [ ] `THIRD_PARTY_NOTICES.md` exists
- [ ] `DISCLAIMER.md` exists
- [ ] `legal.html` is reachable from the footer

## Local validation

```bash
node --check app.js
python scripts/validate_data.py
```

No `dashboard.json` regeneration is required for the v1.0 UI/documentation finalization itself.
