# Threat Investigation

> **v1.0.0 — Stable Release**  
> Security Intelligence Platform の **Investigate / Relate** レイヤー。

Threat Investigation は、MITRE ATT&CK® Enterprise を基盤に、Threat Actor / Software / Technique / Platform を起点として、ATT&CK に記録された Evidence と Relationship を短時間で確認するための静的 Web ツールです。

Security Intelligence Library の **Observe / Interpret** と、Vulnerability Intelligence の **Prioritize** の間をつなぎます。

```text
Security Intelligence Library
        Observe / Interpret
                ↓
        Threat Investigation
         Investigate / Relate
                ↓
     Vulnerability Intelligence
            Prioritize
                ↓
               Act
```

## v1.0 の設計原則

1. **Search-first** — 種別が分からなくても name / alias / ATT&CK ID から検索開始できます。
2. **Entity Resolution と Investigation を分離** — 曖昧な検索語を勝手に調査対象へ確定しません。
3. **Finding first** — STEP 3 は Finding を主役にし、Context / Evidence / Further Investigation は必要なときだけ参照します。
4. **Evidence boundary を明示** — Direct Match、ATT&CK Relationship、Environment Overlay、Dashboard-derived view を混同しません。
5. **No risk score** — ATT&CK の関係件数や Dashboard 独自 Lens を危険度・攻撃可能性・対策優先度として扱いません。
6. **Environment is optional** — My Environment 未登録でも調査できます。Environment Overlay は任意です。

## v1.0 の対象

- Threat Actor: ATT&CK Group (`intrusion-set`)
- Software: ATT&CK Malware / Tool
- Technique: ATT&CK Technique / Sub-technique
- Platform: ATT&CK Platform metadata を起点に関連 Entity を調べる Investigation target
- Campaign: Profile / Explorer での関連調査対象

Platform は独立した STIX Entity ではないため、Technique / Software / Actor と同じ意味での Profile は作りません。

## 主な機能

- Search scope: `All / Threat Actor / Software / Technology`
- ATT&CK ID / name / alias / prefix / contains による Entity Resolution
- 同順位候補が複数ある場合の明示的な Target 選択
- General を既定とする Investigation Context
- Identity / Internet-facing / Virtualization / Server / Cloud Lens
- 任意の Environment Overlay
- Sticky Launch Bar による Target / Lens / Overlay の確認
- Finding → Context → Evidence → Further Investigation の読解フロー
- Threat Actor / Software / Technique / Campaign Profile
- Platform 起点の Investigation Result
- Entity 間の ATT&CK direct relationship drill-down
- 長い Related Entity リストの `+N more / Show less` 展開
- Shared Environment Profile (`peridotan-security-environment-v1`)
- Security Intelligence Library からの Navigation Context 受け取り
- Vulnerability Intelligence への Context-preserving navigation
- Browser-readable MIT License / Legal & Data Notice

## Evidence semantics

### Direct Match
ATT&CK ID / name / alias の一致です。検索語と Entity の対応を示します。

### ATT&CK Relationship
現在読み込んでいる ATT&CK dataset に記録された直接関係です。共通 Technique などから推定した関係は含めません。

### Investigation Lens
調査時の閲覧観点です。General は絞り込みなし。Curated Lens は調査しやすくするためのビューで、MITRE の公式分類ではありません。

### Environment Overlay
My Environment と Evidence の接点を追加表示する任意レイヤーです。リスクスコア、攻撃証拠、標的化の断定ではありません。

### Defensive Investigation Lenses
Threat Actor Profile の Dashboard-derived view です。ATT&CK Tactics を防御側の調査観点で再構成します。MITRE ATT&CK の正式分類、Control mapping、対策優先度、リスクスコアではありません。

## Profile の読み方

Profile は Entity 固有情報を優先し、Investigation Context は小さなメタ情報として扱います。

Threat Actor Profile の主要順序は次のとおりです。

```text
Techniques → Tactics → Software → Campaigns → Aliases
```

Software / Technique / Campaign も同じ原則で、上部 metrics と下部 sections の順序を揃えています。0 件は「現在の loaded ATT&CK dataset に direct relationship が記録されていない」ことを示すだけで、実世界で関係が存在しないことを意味しません。

## Security Intelligence Platform との役割分担

| Layer | Tool | 主な問い |
|---|---|---|
| Observe / Interpret | Security Intelligence Library | 何が起きているか |
| Investigate / Relate | Threat Investigation | 誰が・何を・どう使い、何と関係するか |
| Prioritize | Vulnerability Intelligence | 何を優先すべきか |
| Act | 組織の運用 / 対応 | 何を実行するか |

Threat Investigation はニュース収集ツールでも Vulnerability prioritization engine でもありません。Current Intelligence は Navigation Context として受け取り、ATT&CK Evidence と混同しません。

## Cross-tool navigation

Entity deep link:

```text
?entity=actor:G0032
?entity=software:S1242
?entity=technique:T1059.001
?entity=platform:ESXi
```

Security Intelligence Library から Navigation Context を渡す例:

```text
?entity=software:S1242&from=security-intelligence-library&context=2026-09-qilin-esxi&contextTitle=Qilin%20activity%20involving%20ESXi
```

詳細は `INTEGRATION_CONTRACT.md` を参照してください。

## Local run

```bash
python scripts/update_attack.py
python scripts/validate_data.py
python -m http.server 8000
```

`http://localhost:8000/threat-investigation-dashboard/` を開きます。`file://` 直開きでは JSON fetch が失敗する場合があります。

UI のみ更新する場合、data schema が変わっていなければ `dashboard.json` の再生成は不要です。

## GitHub Pages

推奨 repository 名:

```text
threat-investigation-dashboard
```

GitHub Actions で ATT&CK data を取得・整形・検証し、成功したデータだけを Pages に公開する構成を想定しています。

## Data source and trademark

This project makes use of MITRE ATT&CK®.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. Use of ATT&CK data does not imply affiliation with, sponsorship by, or endorsement by MITRE.

- ATT&CK: https://attack.mitre.org/
- STIX data: https://github.com/mitre-attack/attack-stix-data
- Terms: https://attack.mitre.org/resources/terms-of-use/

## License

Dashboard source code: MIT License. See `LICENSE` and browser-readable `license.html`.

Third-party data is subject to the source provider's terms. See `THIRD_PARTY_NOTICES.md`, `DISCLAIMER.md`, and `legal.html`.

## Documentation

- `ARCHITECTURE.md` — Platform role / Observe → Investigate → Prioritize → Act
- `INTEGRATION_CONTRACT.md` — Entity deep link / Navigation Context
- `INVESTIGATION_MODEL.md` — Investigation semantics
- `ROADMAP.md` — v1.1+ candidates
- `RELEASE_CHECKLIST.md` — v1.0 release checks
- `CHANGELOG.md` — version history
