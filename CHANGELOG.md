## v1.0.3 — Font size control

- Added an `Aa 文字サイズ` control with `標準 / 大 / 特大` options.
- Stores the selected display size in localStorage and restores it on the next visit.
- Scales existing dashboard typography without changing ATT&CK data or evidence semantics.
- Added `font-size.css` / `font-size.js` and included them in the GitHub Pages artifact.
- Updated static asset cache-busting to v1.0.3.
- No ATT&CK data schema change; `dashboard.json` regeneration is not required for this UI release.

## v1.0.2 — Platform Result consistency

- Added Campaigns to the Platform Finding metric row.
- Aligned Platform Finding cards with the Finding sentence and Further Investigation: Software → Techniques → Actors → Campaigns.
- Preserved evidence semantics by marking Software / Techniques as Platform metadata exact and Actor / Campaign counts as reconstructed investigation context.
- Updated JavaScript cache-busting to v1.0.2.

## v1.0.1 — Platform profile semantics clarification

- Added a compact Platform Context note to Platform Investigation results.
- Clarified that ATT&CK Platform values such as ESXi and Windows are metadata attached to Technique / Software rather than standalone profile entities.
- Preserved Platform drill-down into related Software / Techniques / Actors / Campaigns.
- Updated static asset cache-busting to v1.0.1.

## v1.0.0 — Stable Threat Investigation release

- Product / directory naming is finalized as **Threat Investigation** / `threat-investigation-dashboard`.
- v1.0 scope is frozen around Search-first Entity Resolution, Investigation Context, Finding-first Result, Profile drill-down, Platform investigation, optional Environment Overlay, and sibling-tool navigation.
- STEP 3 copy is aligned to `Finding → Context → Evidence → Further Investigation`; Context is intentionally secondary to Finding.
- Added canonical `LICENSE`, `COPYRIGHT.md`, `THIRD_PARTY_NOTICES.md`, and refreshed `DISCLAIMER.md` / Legal documentation for public release.
- README is rewritten around the current architecture instead of historical version-by-version behavior.
- Long related-entity lists keep the v0.8.1 `+N more / Show less` progressive-disclosure behavior.
- Static asset cache-busting updated to v1.0.0.
- No ATT&CK data schema change; `dashboard.json` regeneration is not required for this UI/documentation release.

## v0.8.1 — Expandable relationship lists

- `+N more` in Profile relationship lists is now interactive.
- Expands remaining Actor / Technique / Software / Campaign chips inline and can collapse them again.
- Search scope label is now `Technique / Platform`; Quick Start badges use `Technique` for PowerShell and `Platform` for ESXi.
- Static asset cache-busting updated to v0.8.1.

## v0.8.0 — Threat Investigation / Security Intelligence Platform Architecture v1

- Renamed the product UI from Threat Actor Intelligence Dashboard to **Threat Investigation**.
- Defined Threat Investigation as the **Investigate / Relate** layer between Security Intelligence Library and Vulnerability Intelligence.
- Added `ARCHITECTURE.md`, `INTEGRATION_CONTRACT.md`, and rename migration guidance.
- Added stable `?entity=` deep-link resolution for Actor, Software, Technique, and Platform; Campaign deep links open Profile / Explorer context.
- Added optional `from`, `context`, and `contextTitle` navigation metadata for future Current Intelligence handoff. Navigation context is explicitly not ATT&CK evidence.
- Preserved legacy Explorer query parameters and existing localStorage keys.
- Updated static asset cache-busting to v0.8.0.
- ATT&CK data schema unchanged; `dashboard.json` regeneration is not required.

## v0.7.14 — Lens clarity + small consistency polish

- Threat Actor Profileの `Defensive Relevance` を `Defensive Investigation Lenses` に改称し、重要度評価ではなく調査Lensであることを明確化。
- Defensive Investigation Lensesは最大6 Lensとし、`4 of 6 lenses represented` のように該当Lens数を表示。Techniqueが複数Lensに現れ得ることを注記。
- `Stealth & Defense` の説明に Defense Evasion を明示。
- 件数が1の場合は `1 platform` / `1 tactic` / `1 actor` など単数形で表示し、Result / Profileの表記を整理。
- 展開中Profileの一覧ヘッダーをわずかに弱め、Profile本体との情報重複感を軽減。
- FooterのMIT Licenseリンクをブラウザ閲覧用 `license.html` へ変更。リポジトリの `LICENSE` はcanonical fileとして維持。
- `style.css` / `app.js` のcache-busting queryをv0.7.14へ更新。
- ATT&CKデータスキーマ変更なし。`dashboard.json` の再生成は不要。

## v0.7.13 — Generic profile information architecture

- Threat Actorで確立したProfileの読み方をSoftware / Technique / Campaignへ横展開。
- Software Profileを `Actors → Techniques → Campaigns → Platforms → Aliases` のCanonical Orderへ再構成。
- Technique Profileを `Actors → Software → Campaigns → Platforms → Tactics → Aliases` のCanonical Orderへ再構成。
- Campaign Profileを `Actors → Techniques → Software → Observed Period → Aliases` のCanonical Orderへ再構成。
- `Related Intelligence` の曖昧な見出しを各Profileから廃止し、具体的なEntity / attributeセクションに統合。
- Software / Technique / Campaignにも `ATT&CK OVERVIEW` とコンパクトなInvestigation Contextを適用。
- Profile headerの主要メトリクスとページ下部の読み順をEntityごとに一致。
- Platformは独立したATT&CK STIX Entityではないため、Profileを新設せずPlatform metadata起点のInvestigation Resultを維持。
- `style.css` / `app.js` のcache-busting queryをv0.7.13へ更新。

## v0.7.12 — Profile information architecture + navigation

- Threat Actor Profileを `Techniques → Tactics → Software → Campaigns → Aliases` のCanonical Orderで再構成。
- `Detailed Techniques by Tactic` をトップレベル見出しから外し、Techniques内の表示方法（Group Techniques by Tactic）へ変更。
- 曖昧な `Related Intelligence` 見出しを廃止し、Software / Campaignsなど具体的なEntityセクションへ統合。
- Aliasesを独立した正式セクションへ移動。
- Defensive Relevanceを `DASHBOARD ANALYSIS` としてATT&CK由来情報から明確に分離。
- ATT&CK OverviewにOriginal Description / referenced platforms / modified dateを集約し、重複表示を削減。
- Threat Actor Profileの主要メトリクスを `Techniques / Tactics / Software / Campaigns / Aliases` の5指標に統一。
- 長いProfile / Further Investigation向けに、一定量スクロールすると表示される固定 `↑ Top` ボタンを追加。
- `style.css` / `app.js` のcache-busting queryをv0.7.12へ更新。

## v0.7.11 — Result / Profile hierarchy + interaction polish

- ③ Investigation ResultではFINDINGを主役として強調し、General + Overlay未使用時のContextを1行へ圧縮。
- Evidence / Further Investigationを補助情報としてコンパクト化。
- Threat Actor Profileでは大きなInvestigation Contextカードを廃止し、Entity情報を妨げないメタ情報行へ縮小。
- Threat Actorの主要指標は `Techniques → Tactics → Software → Campaigns → Aliases` を共通順序として維持。
- クリック可能要素のhoverを薄い青背景＋青枠に統一し、Selected（緑）/ Disabled（無変化）と視覚的に区別。
- `style.css` / `app.js` のcache-busting queryをv0.7.11へ更新。

## v0.7.10 — UI hierarchy + context safety

- トップを Hero / Help / Work Area の3層として整理し、主要操作をInvestigation Setupへ集中。
- 右上をSuite navigationとReference linksに分離し、外部リンクの視覚的な主張を抑制。
- 「このツールの使い方」と「表示の読み方」を1つのHelp hubへ統合。
- Help / version / dataset metadataの文字サイズ・色・余白を補助情報として再調整。
- Investigation Setupは検索側を広く、Context側をコンパクトにして情報密度を改善。
- Further InvestigationでEntity種別を切り替えた場合、Tactic / Platformの一時フィルタを自動解除し、別Entityの件数を誤読しないよう修正。
- `style.css` / `app.js` のcache-busting queryをv0.7.10へ更新。

## v0.7.9 — Resolution UX consistency + generic Result attributes

- Prefix入力（例: `pan` / `pand`）ではPrefix候補だけでなく有力なContains候補も同じ候補一覧に表示。Exact以外は自動確定しない方針を維持。
- FindingのTarget Profile導線を左側へ寄せ、視線移動を削減。
- AliasesをFinding内でクリックしてインライン展開可能に変更。
- Software / TechniqueでもPlatforms / Tactics / Aliasesを同じ「属性はその場で展開」ルールに統一。
- 関連EntityはExplorerへドリルダウン、Target自身はProfile、属性情報はインライン展開というResult UIルールを共通化。
- `style.css` / `app.js` のcache-busting queryをv0.7.9へ更新。

## v0.7.8 — Resolution safety + Tactic drill-down

- Prefix / contains matches no longer auto-select an investigation target while the user may still be typing. Only exact / canonical-exact matches auto-resolve.
- Fixes the `pan` → `Pandora` premature selection problem when the intended query is `panda`.
- Adds clickable Tactic Coverage to Threat Actor FINDING results.
- Tactic drill-down lists each ATT&CK tactic with its related technique count; selecting a tactic opens only the actor's techniques for that tactic.
- Further Investigation now includes Tactic Coverage in the same order as FINDING.

## v0.7.7 — Asset cache reliability

- Versioned `app.js` and `style.css` URLs (`?v=0.7.7`) so a new release does not keep rendering an older cached UI.
- Keeps the v0.7.6 Result hierarchy changes: Target Profile link in FINDING, compact General context, and aligned Further Investigation order.

## v0.7.6 — Result Information Hierarchy

- Added TARGET Profile action inside FINDING for Actor / Software / Technique.
- Compressed General Lens into Investigation Context.
- Renamed the expanded non-General block to LENS RELEVANCE.
- Aligned Further Investigation with FINDING order and removed duplicate Full Profile action.
- Suppressed zero-count Further Investigation branches.
- Added Campaign drill-down to Software where ATT&CK relationships exist.

## v0.7.5 — Context-first Launch / Sticky Start

- Candidate選択時のinline Start actionを削除し、STEP 1はTarget確定だけを担当するようにした。
- STEP 2のInvestigation Contextは `General` + `Environment Overlay: Not used` を標準状態としてコンパクト表示。
- `Contextを変更` で詳細Lens / Overlay設定を展開するProgressive Disclosureへ変更。
- Target確定後、Target / Lens / Overlayを表示するSticky Launch Barを画面下部に固定表示。
- Investigation実行ボタンをLaunch Barへ一本化し、STEP 2のContextを確認しやすくした。
- Search queryでEnterを押しても自動実行しないよう変更。Search / Resolve / Executeを分離。
- Search queryは選択後も保持し、Selected Targetと別の状態として扱う。
- ATT&CKデータスキーマ変更なし。`dashboard.json` の再生成は不要。

## v0.7.4 — Entity Resolution UX / Visible Investigation Action

- Entity Resolutionの候補を `BEST MATCHES` と `OTHER MATCHES` に分離し、同順位最上位候補と一致度の低い候補を混在表示しないようにした。
- `panda` のような曖昧検索では、最上位候補だけを常時表示し、その他の一致候補は折りたたみで確認できる。
- 調査対象を選択・自動解決した直後のResolution statusに `対象 × Lens を調査` ボタンを追加。候補一覧が長くても画面下部までスクロールせず調査を開始できる。
- 既存のSetup下部のInvestigation launch barは全体サマリーとして維持。
- 曖昧な候補を勝手に確定しないEntity Resolutionルールは変更しない。

## v0.7.3 — Search-first Generic Entity Resolution

- Category-first Investigation EntryをSearch-firstへ変更。
- `All / Threat Actor / Software / Technology` を検索フィルターとして再定義。
- Threat Actor / Software / Technique / ATT&CK Platformを共通Entity Resolverで扱う。
- top-scoreが1件ならauto resolve、同順位複数ならcandidate selection必須。
- Quick Startは入力補助のみ。自動実行しない。
- ExplorerをFurther InvestigationとしてSetup stateから分離。

# Changelog

## v0.7.0

- Technology Investigationを正式化。ATT&CK Technique / Softwareだけでなく、ATT&CK Platform（例: ESXi）を調査起点として扱えるようにした。
- `VMware ESXi` / `ESXi` などの保守的な名称正規化からPlatform Investigation Resultを生成する。
- Platform Resultでは関連Software / Technique / ActorをATT&CK metadataから集計し、件数からそのPlatformに絞ったExplorerへドリルダウンできる。
- Actor件数はActor自身のPlatform属性ではなく、ATT&CKでActorに直接紐付くTechnique / SoftwareのPlatform metadataから再構成した閲覧用集計であることを明示。
- Platform共有だけからActor ↔ Product / Actor ↔ CVE / リスクを推定しないEvidence境界を維持。
- Quick Startに `Platform · ESXi` を追加。

## v0.6.9 — 2026-09-10

### Changed
- Generic Investigation ResultをTechniqueまで拡張。
- Result内の関連件数とRelevance件数をドリルダウン可能に変更。
- Relevance件数は同一Result内のDirect / Normalized / Context詳細へ移動。
- FindingのActor / Technique / Software / Campaign件数は、現在EntityとのATT&CK relationshipを維持してExplorerへ移動。
- Context Only詳細にVulnerability Intelligenceへの導線を追加。

### Concept check
- 本ツールはATT&CKデータベースの単純な一覧ではなく、`調査対象 × Investigation Scope` から「何が分かったか」「自環境との接点は何か」「次に何を見るか」を判断するためのInvestigation Toolとする。
- Environment Profileは資産台帳やリスクスコアではなく調査Context。
- Normalized overlapは閲覧補助でありATT&CK relationshipではない。Actor ↔ CVEはEvidenceなしに推定しない。

## v0.6.8 — 2026-09-10

- Changed Further Investigation > Full Profile to preserve the current investigation subject and show only that Entity in Explorer, instead of reopening the full catalog.
- Added focused-profile Explorer context and a clear path back to the full catalog.
- Collapsed Evidence by default so Finding and Why it matters remain the primary Result reading path.
- Clarified the semantic difference between Normalized Environment Overlap (environment-level browsing aid) and Context Only (Vulnerability Intelligence hand-off context).
- Collapsed Environment Profile at the top level and treated it as settings rather than part of the primary investigation flow.
- Increased key text sizes and refined semantic colors across Setup, Result, Further Investigation, Settings, and Explorer.
- No ATT&CK data-schema changes.

## v0.6.7

- Added three-level relevance semantics: Direct ATT&CK Match / Normalized Environment Overlap / Context Only.
- Added conservative Product → ATT&CK Platform normalization, including VMware / ESXi → ESXi.
- Renamed Next Investigation to Further Investigation and clarified it is optional within STEP 3, not STEP 4.
- Reworked the on-screen usage guide to align with the real STEP 1–3 workflow.
- Reframed My Environment as a compact, collapsed Environment Profile settings area.
- Collapsed dataset-wide KPI / coverage panels into an optional ATT&CK Dataset Overview.

# CHANGELOG

## v0.6.6 — 2026-09-10

- Quick Start now fills Entry type + query only; it never starts or scrolls the investigation.
- Changing Setup returns Investigation Result to a waiting state until Start Investigation is pressed.
- In-page usage guide is visually separated from the actual STEP 1–3 controls and no longer uses competing step numbers.
- Investigation Result is reorganized as Finding → Why it matters → Next investigation → Evidence.
- Explorer is explicitly labeled as an optional further-investigation layer.
- Quick Start chips now show Actor / Software / Technology type labels.

## v0.6.4 — 2026-09-10

- Reworked the main flow into **Setup → Result → Explorer**.
- Moved **Start Investigation** below Entry and Scope so execution occurs only after both conditions are defined.
- Added a full-width **Investigation Result** area for Summary, Why it matters, Related/How, and Evidence.
- Added Investigation-centric result rendering for Threat Actor and Software entries.
- Added an on-screen **このツールの使い方** manual, including interpretation cautions.
- Preserved user-defined Investigation Scopes and cross-dashboard My Environment behavior.

## v0.6.3

- Synchronized Investigation Workflow with the Intelligence Explorer.
- Selecting Threat Actor / Software / Technology now switches the Explorer to the corresponding investigation view before the user starts the search.
- `調査を開始` carries the Workflow query into Explorer and opens a single strongest direct match when one exists.
- Technology entry resolves exact Technique / Software matches to the matching canonical profile; ambiguous or broad searches remain in the most relevant Explorer view.
- Explorer tab changes and Explorer search now synchronize back to the Workflow entry/query state.
- `Explorerで詳しく見る` keeps the current focused entity when available, otherwise applies the current Workflow state before scrolling.
- Vulnerability entry continues to open Vulnerability Intelligence in My Environment scope; the investigation query is carried as URL context for future consumption.
- No ATT&CK data-schema changes.

## v0.6.2

- Changed named Investigation Scopes (Identity / Internet-facing / Virtualization / Server / Cloud) from automatic string-rule classification to user-defined reusable environment sets.
- Added browser-local scope store `peridotan-investigation-scopes-v1`.
- Scope template rules remain available only as explicit suggestions; they are never applied automatically and are not treated as threat evidence.
- Added per-scope editor using items already registered in My Environment.
- Improved `WHY IT MATTERS` semantics: unconfigured Platform/Technology now shows `Not configured` instead of `0 / 0`.
- Product items are listed explicitly as `Vulnerability context only — not Actor evidence`.
- No ATT&CK data-schema changes.

## v0.6.1

- Fixed Investigation Entry `調査を開始` for entities outside the Explorer 500-card render cap.
- Focused canonical entities are now moved to the front of the rendered list so Software such as Qilin (S1242) can always open and scroll into view.
- No data-schema changes.

# Changelog

## v0.6.0

- Added Investigation Workflow as the primary interaction model.
- Added Investigation Entry for Threat Actor, Software, Technology and Vulnerability paths.
- Added reusable preset Investigation Scopes and Custom Scope selection from My Environment.
- Reframed Actor environment overlap as `WHY IT MATTERS TO THIS INVESTIGATION`.
- Scope narrows the investigation lens without mutating the shared My Environment profile.
- Kept Product as vulnerability context only; no Actor→CVE relationship is inferred.
- Changed focused Actor landing position to the profile top for easier investigation.

## v0.5.0 — Environment Context Navigation

- Added sibling navigation for Threat Actor Intelligence, Vulnerability Intelligence, and Security Intelligence Library.
- Added My Environment bridge to Vulnerability Intelligence.
- Actor Profile can open the Vulnerability My Environment view with actor context, without asserting Actor-to-CVE causality.
- Added URL launch parameters for deep-linking to a focused ATT&CK entity.


## v0.4.2 — Technology display normalization

- Shared My Environment の既知Technology表記を正規化（例: `powershell` → `PowerShell`）。
- 正規化は表示・入力品質の補助であり、ATT&CK上の関連性や脅威度を意味しません。
- 共通localStorageキー `peridotan-security-environment-v1` とスキーマは変更しません。


## v0.4.2 — My Environment input quality

- Added Vendor / Product canonicalization for a small built-in set of common products.
- Added datalist suggestions for known Vendor / Product names while keeping free-form registration available.
- Added mismatch detection when a Product name maps uniquely to a different known Vendor (for example `windows / esxi` → suggestion `VMware / ESXi`).
- Mismatched existing entries are never changed automatically; users can apply a displayed correction candidate explicitly.
- Legacy Vulnerability Watchlist import now normalizes recognized product names before merging into the shared profile and shows an import preview.
- The canonical catalog is an input aid only, not an authoritative product inventory or vulnerability source.
- Shared environment schema and ATT&CK dataset schema are unchanged; no data regeneration is required.

## v0.4.0 — Shared My Environment foundation

- Added browser-local shared environment schema (`peridotan-security-environment-v1`).
- Added independent Platform / Vendor-Product / Technology editor.
- Vendor/Product entries are no longer limited to products present in ATT&CK, KEV, or Emerging datasets.
- Added optional import from the existing Vulnerability Intelligence watchlist without deleting legacy keys.
- Added Actor Profile `My Environment Relevance` using explainable platform overlap and exact ATT&CK Technique / Software entity matches only.
- Product entries are stored for future Vulnerability Intelligence correlation and are not used as Threat Actor risk evidence in v0.4.0.
- Added cross-tab storage synchronization for dashboards running on the same origin.
- Added `MY_ENVIRONMENT_SCHEMA.md` and deployment of `environment.js`.
- No ATT&CK dataset schema change; `update_attack.py` re-run is not required.

## v0.3.3 - 2026-09-09

- Entity-aware SearchのDirect MatchとATT&CK Relationship結果を完全に分離し、Primary Matchを選択中タブの一覧へ重複表示しないよう変更。
- Direct Matchカードに一致根拠（ID / name / alias、exact / prefix / contains）を表示。
- Related Entityには `ATT&CK RELATIONSHIP` バッジと関係理由を表示。
- 同一Entity種別を検索した場合の下段一覧を `Additional ... related to ...` とし、Direct Matchとの役割を明確化。
- 共通Techniqueなどから推定するDerived / analytical relationshipは表示しない方針をUI上に明記。
- Related result countを `関連 N件` と表示し、Direct Match件数と混同しないよう改善。
- データスキーマ変更なし。v0.3.2からの更新ではデータ再生成不要。

## v0.3.2 - 2026-09-09

- Entity-aware Searchで強い直接一致がある場合、説明文などの単なる文字列一致をRelated Entityとして混在させず、直接一致またはATT&CK関係データで根拠を説明できる結果だけを表示。
- Related Entityが0件のとき、`該当するデータがありません` ではなく「ATT&CK上で直接関連付けられたEntityはない」と明示。
- Campaign 0件時は、実世界の攻撃活動やベンダー報告上のCampaignが存在しないことを意味しない旨を表示。
- 0件表示が現在読み込まれているMITRE ATT&CKデータの直接関係に基づくことを明記。
- データスキーマ変更なし。v0.3.1からの更新ではデータ再生成不要。

## v0.3.1 - 2026-09-09

- Actor Profile の `Detailed Techniques by Tactic` を初期状態で折りたたむ compact view に変更。
- Tactic ごとにクリックして展開 / 閉じる操作を追加。
- `すべて展開` / `すべて閉じる` を追加。
- Tactic Coverage カードをクリックすると、該当 Tactic の詳細だけを展開してスクロールするよう改善。
- Technique チップから Technique Profile への既存ナビゲーションを維持。
- データスキーマ変更なし。v0.3.0 / v0.2.x からの更新ではデータ再生成不要。

## v0.3.0 - 2026-09-09

- Added a Threat Actor Investigation Summary to the Actor profile
- Added referenced-platform aggregation across related Techniques and Software
- Added Defensive Relevance, a dashboard-derived six-lens view for finding ATT&CK Techniques from common defender perspectives
- Added direct Technique navigation inside each defensive lens
- Added explicit notices that Defensive Relevance is not an official ATT&CK taxonomy, control mapping, priority score, or environment-specific risk assessment
- Kept the v0.2.0 data schema unchanged; ATT&CK data regeneration is not required when updating from v0.2.x

## v0.2.1 - 2026-09-08

- Added a dynamic related-result heading for the currently selected Explorer tab, such as `Related Techniques for Qilin`
- Added a concise relationship reason to each list result, such as `Associated with software: S1242 Qilin`
- Generalized the cross-search helper text so it describes related Entities rather than only related Actors
- Kept the v0.2.0 data schema unchanged; no ATT&CK data regeneration is required when updating from v0.2.0

## v0.2.0 - 2026-09-08

- Added Entity-aware Search across Actor / Technique / Software / Campaign
- Direct matches are shown independently of the currently selected Explorer tab
- Added Related Threat Actors for direct Technique / Software / Campaign matches, making searches such as `Qilin` explain the ATT&CK entity classification and linked Groups
- Added focus navigation that opens the selected entity profile directly
- Expanded Technique Detail with related Actors / Software / Campaigns
- Expanded Software Detail with related Actors / Techniques / Campaigns / Platforms
- Expanded Campaign Detail with related Actors / Techniques / Software and observed period
- Extended generated JSON with reverse Software ⇄ Technique, Software ⇄ Campaign, and Technique ⇄ Campaign relationships
- Extended dataset validation to check cross-entity references and reverse relationship consistency
- Added data schema version metadata (`0.2.0`)

## v0.1.2 - 2026-09-08

- Changed desktop Tactic Coverage to a five-column layout, yielding a clean 5 x 3 presentation when all 15 Enterprise tactics are present
- Aligned Tactic ordering with the current Enterprise Matrix, including Stealth and Defense Impairment
- Clarified that a Technique may belong to multiple Tactics, so Tactic totals can exceed Unique Techniques
- Removed the canonical Actor name from the Alias chips and collapsed Alias summary
- Added an explicit `MITRE ATT&CK Description (original)` label above source descriptions
- Renamed the Actor detail counter to `unique techniques` for clearer interpretation

## v0.1.1 - 2026-09-08

- Expanded Actor Detail into a Threat Actor Profile
- Added full Alias display and explicit Alias-aware search
- Added ATT&CK Tactic coverage per Actor
- Added Techniques by Tactic drill-down
- Added direct navigation to all related Techniques / Software / Campaigns
- Added active context display and safe context reset for cross-navigation
- Clarified KPI labels as Unique Techniques / Unique Software
- Preserved warning that relationship counts are not threat or activity rankings

## v0.1.0 - 2026-09-08

- Initial Threat Actor Intelligence Dashboard scaffold
- ATT&CK Groups / Techniques / Software / Campaigns
- Cross-entity explorer
- Tactic and platform filters
- Automated STIX refresh, validation, and GitHub Pages deployment


## v0.7.2

- Aligned the UI with the Investigation concept: Threat Actor / Software / Technology are the first-class investigation entries.
- Moved CVE-first investigation to a clear Vulnerability Intelligence bridge instead of treating Vulnerability as an ATT&CK-native target.
- Re-labeled the ESXi Quick Start as Technology with ATT&CK Platform context.
- Reworded Environment Overlay setup counts as selection counts rather than match-like ratios.
- Collapsed unused Environment Overlay in Result into a compact optional state.
- Applied the same Environment Overlay presentation semantics across Actor, Software, Technique, and Platform results.

## v0.7.1

- Replaced the environment-dependent `Investigation Scope` with an independent **Investigation Lens**.
- Added optional **Environment Overlay**; investigations no longer require My Environment items.
- Split Result semantics into Finding / Lens Relevance / Environment Relevance / Evidence / Further Investigation.
- Added ATT&CK-native vs Dashboard-curated Lens labels to avoid implying MITRE-defined classifications.
- Added compatibility read for legacy `peridotan-investigation-scopes-v1` and new `peridotan-environment-views-v1` storage.
- Kept Vulnerability Intelligence as a hand-off/context destination rather than inferring Actor ↔ CVE relationships.
