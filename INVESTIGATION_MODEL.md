# Threat Investigation Model

> v1.0.0: Security Intelligence Platform Architecture v1 の Investigate / Relate レイヤーとして安定化します。


Entity Profileは「上部メトリクスを、そのまま同じ順番で詳しく読む」構造を共通契約とする。

- Threat Actor: `Techniques → Tactics → Software → Campaigns → Aliases`
- Software: `Actors → Techniques → Campaigns → Platforms → Aliases`
- Technique: `Actors → Software → Campaigns → Platforms → Tactics → Aliases`
- Campaign: `Actors → Techniques → Software → Observed Period → Aliases`

`Related Intelligence` のような抽象レイヤーはProfileでは使わず、具体的なEntity / attribute名を直接セクション見出しにする。`ATT&CK OVERVIEW` はsource entityの説明、type、modified date等に専念し、Investigation Contextは補助メタ情報として小さく表示する。ATT&CK Platformは独立STIX EntityではないためProfileを作らず、Platform metadata起点のResult / drill-downとして扱う。

## v0.7.12 Profile information architecture

Threat Actor ProfileのCanonical Orderは `Techniques → Tactics → Software → Campaigns → Aliases`。Defensive RelevanceはATT&CK relationshipではなくDashboard Analysisとして別レイヤーに表示する。

## v0.7.11 — Visual hierarchy and interaction contract

- Result hierarchy: `FINDING` is primary. General / no-overlay context, Evidence, and Further Investigation are visually secondary.
- Profile hierarchy: the ATT&CK Entity is primary. Investigation Context is metadata, not the main profile content.
- Threat Actor canonical metric order: `Techniques → Tactics → Software → Campaigns → Aliases` whenever those metrics are shown together.
- Interaction states: actionable elements use a light-blue hover; selected targets remain green; disabled/non-actionable counts do not react on hover.

## v0.7.10 — UI hierarchy and local drill-down context

- Primary workflow: Search & Select Target → Investigation Context → Result.
- Help / references / version metadata are secondary to the investigation workflow.
- Tactic / Platform filters created during Further Investigation are local drill-down context. They are cleared when moving to a different entity type unless the new action explicitly supplies its own filter.

## v0.7.9 — Result interaction contract

Result内の操作をEntity種別に依存しない3種類へ統一します。

1. **Target itself** → Profileへ移動。
2. **Related entities** → 現在のInvestigation contextを保ってExplorerへドリルダウン。
3. **Attributes**（Aliases / Platforms / Tactics等）→ Result内でインライン展開。

Entity ResolutionはExact matchだけ自動確定し、Prefix / Containsは候補提示に留めます。入力途中のPrefixでは下位のContains候補も見えるようにし、候補全体像を隠しません。

## v0.7.8 — Incremental search safety and Tactic Coverage

Entity Resolution must not confuse a transient prefix with a confirmed target. Exact name / ID / alias / canonical platform matches may auto-resolve; prefix and contains matches always require explicit user selection. Threat Actor results expose Tactic Coverage as a drill-down derived from the actor's related ATT&CK techniques.

## v0.7.7 — Asset cache reliability

Static UI assets are versioned at load time. This is an operational delivery fix; the investigation model is unchanged from v0.7.6.

## v0.7.6 — Result information hierarchy

Result separates the selected target, ATT&CK facts, context and optional drill-down.

1. FINDING answers what ATT&CK records and exposes the canonical TARGET Profile.
2. General is treated as compact Investigation Context, not a large analytical result.
3. Non-General lenses show LENS RELEVANCE only when the lens contributes a meaningful analytical perspective.
4. Further Investigation follows the same entity ordering as FINDING and only shows branches that can actually be opened.
5. Full Profile is not repeated in Further Investigation; it belongs to the TARGET in FINDING.

## v0.7.5 — Target / Context / Execute separation

Investigation Setupの操作責務を3段階に分離します。

```text
Search query
  ↓
Entity Resolution
  ↓
Confirmed Target                 ← STEP 1
  ↓
Investigation Context
  Lens: General (default)
  Environment Overlay: Not used  ← STEP 2
  ↓
Sticky Launch Bar
  Target / Lens / Overlayを確認
  ↓
Investigation Result             ← STEP 3
```

- Candidateのクリックは **Target確定だけ** を行い、調査を開始しません。
- Lensは必須概念ですが、ユーザーに毎回選択を要求しません。既定値 `General` を明示して利用できます。
- STEP 2は通常Current Contextだけを表示し、変更時のみ詳細Lens / Overlay設定を展開します。
- Investigation実行はSticky Launch Barの単一Start actionに集約します。
- Launch BarにはTarget / Lens / Environment Overlayを常時明示し、暗黙のContextで実行しないようにします。
- Search queryとConfirmed Targetは別状態です。曖昧検索の入力履歴を維持したまま、ATT&CK Entityを一意に確定します。

## v0.7.4 — Entity Resolution presentation rules

Entity Resolutionは検索結果の件数そのものではなく、**一致度の階層と確定状態**を明確に見せます。

- `BEST MATCHES`: 現在の検索語で最高スコアの候補。複数件なら明示選択が必要。
- `OTHER MATCHES`: lower-score candidate。補助候補として折りたたみ表示。
- Target確定後はResolution status内にStart actionを置き、Candidate listの長さに依存せず調査を開始できるようにする。
- Start actionはInvestigation Lensの現在値を反映する。Environment Overlayは任意なのでStartの可否には影響しない。
- 下部launch barは全体Contextのサマリーとして残し、inline Start actionと同じ `startInvestigation()` を実行する。

## v0.7.3 — Search-first Entity Resolution

STEP 1の責務は「Entity Typeを先に選ぶ」ことではなく、ユーザーの入力から **調査対象を一意に確定する** ことです。

```text
User input
  ↓
Search scope (All by default)
  ↓
Entity Resolution
  ├─ ATT&CK ID exact
  ├─ Name exact
  ├─ Alias exact
  ├─ Prefix
  ├─ Contains
  └─ ATT&CK Platform resolution
  ↓
0 candidates      → Not found / Explorer
1 strongest       → Auto resolved
Tied strongest    → User selects one
  ↓
Confirmed Target
  ↓
Investigation Lens
  ↓
Optional Environment Overlay
  ↓
Investigation Result
```

`Threat Actor / Software / Technology` は必須の事前選択ではなく検索範囲を狭めるFilterです。Technologyは利用者向けの入口であり、ATT&CK Technique / Software / Platformへ解決されます。

重要な原則は **曖昧な入力を受け付けるが、曖昧なまま分析を開始しない** ことです。ExplorerはFurther Investigation用であり、Explorer側の操作は確定済みInvestigation Targetを書き換えません。

# Investigation-centric model v0.6.7

## Purpose

Threat Investigationを、特定の脅威を短時間で調査し、Evidenceと関係性を確認するInvestigation Layerとして使うためのモデルです。

## Core flow

1. **Investigation Entry** — Threat Actor / Software / Technology / Vulnerabilityから調査を開始
2. **Investigation Scope** — Environment Profile全体ではなく、今回確認する環境範囲を選択
3. **Investigation Result** — Finding / Why it matters / Evidence を確認し、必要な場合だけ Further Investigation へ進む

## Environment Profile vs Investigation Scope

- **Environment Profile (shared My Environment)**: 登録済み環境の長期的なカタログ。多くの項目を保持してよい。
- **Investigation Scope**: その調査で注目する一時的・再利用可能なレンズ。Environment Profile自体を変更しない。

## Investigation Scopes

- `All Environment` はEnvironment Profile全体をそのまま見る固定Scopeです。
- `Identity` / `Internet-facing` / `Virtualization` / `Server` / `Cloud` は、名前だけをあらかじめ用意した**ユーザー定義の再利用Scope**です。
- 各Scopeに含めるPlatform / Product / Technologyは、Environment Profileからユーザーが選択します。
- `Custom` はその場の調査用の一時的な選択です。
- 名称ベースのテンプレート候補は入力補助として明示的に適用できますが、自動分類・Threat relevance・MITRE公式分類としては扱いません。

保存キーは `peridotan-investigation-scopes-v1` です。Environment Profile / shared My Environment (`peridotan-security-environment-v1`) とは独立しているため、Scopeを編集しても資産プロファイルそのものは変更しません。

## Relevance semantics

`WHY IT MATTERS TO THIS INVESTIGATION` は、意味の異なる接点を混ぜずに3段階で表示します。

- **Direct ATT&CK Match**: ATT&CK Platformのexact match、または関連ATT&CK EntityのName / Alias / IDとのexact match。
- **Normalized Environment Overlap**: 明示的なProduct名をATT&CK Platformへ保守的に正規化して確認する閲覧補助。例: `VMware / ESXi` → `ESXi`。ATT&CK relationshipではありません。
- **Context Only**: Vendor / ProductをVulnerability Intelligence側の照合コンテキストとして保持。Actor / Softwareとの直接Evidenceではありません。

Scope overlapは脅威度、攻撃確率、リスクスコアではありません。

## Future direction

次段階では、外部ソースを含むEvidenceが確認できる場合だけ Actor / Software / Campaign ↔ CVE を結び付けます。共通TechniqueやProduct名だけからActor→CVE関係を推定しません。

## Workflow / Explorer synchronization (v0.6.3)

- Investigation Entry is the primary controller for the Explorer view.
- Threat Actor → Actors, Software → Software, Technology → Technique / Software resolution.
- The query entered in the Workflow is passed to Explorer when investigation starts.
- A single strongest direct match opens the canonical entity profile; ambiguous matches remain visible for user selection.
- Explorer tab/search interaction also updates the Workflow state so the two surfaces do not drift apart.
- Campaign remains an Explorer drill-down, not a separate top-level Investigation Entry in v0.6.3.


## v0.6.4 interaction model

1. **Setup**: choose the investigation entry and a user-defined Investigation Scope.
2. **Start**: execute only after the target query and scope are ready.
3. **Result**: read Summary, Why it matters, Related/How, and Evidence before drilling into details.
4. **Explorer**: use the existing entity explorer as the detailed investigation layer, not as the primary result surface.

The Result surface never treats Product context alone as Actor/Software evidence and does not create an independent risk score.


## v0.6.7 interaction semantics

- Quick StartはSetupの入力補助であり、Entry種別とQueryだけを更新する。Quick操作だけではInvestigationを開始しない。
- Investigationの実行境界は `Start Investigation` ボタンに一本化する。
- Entry / Query / Scopeを変更した時点で前回Resultは無効化し、WAITINGへ戻す。
- Resultは `Finding -> Why it matters -> Evidence` を中核とし、必要な場合だけ `Further Investigation` へ進む意思決定面とする。
- ExplorerはSTEPではなく、Resultから必要に応じて降りるOptionalな詳細調査レイヤーとする。
- 画面内Guideは実操作のSTEP 1–3と番号体系を共有しない。Guideは説明、STEP番号は操作状態を示す。


## v0.6.7 semantics

Relevance is presented in three distinct classes:

1. **Direct ATT&CK Match** — exact ATT&CK platform or entity-name / alias / ID match.
2. **Normalized Environment Overlap** — conservative normalization between an explicit Environment Profile product and an ATT&CK platform; this is a browsing aid, not an ATT&CK relationship.
3. **Context Only** — product context passed to Vulnerability Intelligence and not treated as Actor / Software evidence.

Environment Profile is configuration. Investigation Scope is the subset used for the current investigation. Further Investigation is optional and remains inside STEP 3 Result rather than becoming a new numbered step.


## v0.6.8 Result reading and drill-down rules

The primary flow remains **Setup → Result**. Further Investigation is optional and must preserve the current investigation context.

- **Finding**: summarize what ATT&CK currently records for the selected Entity.
- **Why it matters**: separate Direct ATT&CK Match, Normalized Environment Overlap, and Context Only.
- **Evidence**: collapsed by default; open only when the user wants to inspect provenance and inference boundaries.
- **Further Investigation**: related-entity actions remain scoped to the current Entity. Full Profile opens only the current Entity in Explorer.
- **Environment Profile**: settings source for reusable Investigation Scopes; collapsed by default and not treated as a Result.
- **Explorer**: detailed investigation layer. A focused Full Profile view contains one Entity; clearing context returns to the normal catalog.

Semantic intent:

- **Normalized Environment Overlap** = conservative environment-name normalization used to expose an operationally useful overlap. It is not an ATT&CK relationship or attack evidence.
- **Context Only** = Product context retained for Vulnerability Intelligence hand-off. It is not Actor/Software evidence even when the same Product also appears in a normalized overlap.

## v0.7.0 Concept re-check / guardrails

### Original intent and current direction
The original dashboard started from MITRE ATT&CK Groups and their direct relationships to Techniques, Software and Campaigns, with a future goal of connecting that investigation to the Vulnerability Intelligence Dashboard. The investigation-centric design remains aligned with that intent, but changes the primary user experience from **browsing a dataset** to **answering an investigation question**.

The core flow is:

1. **Choose the subject** — Threat Actor / Software / Technology / Vulnerability.
2. **Choose the investigation lens** — a user-defined Scope derived from Environment Profile.
3. **Read the Result** — Finding, relevance to the Scope, evidence boundaries.
4. **Drill down only when needed** — related ATT&CK entities, Full Profile, or Vulnerability Intelligence.

### What the tool is
- An evidence-conscious **Threat Investigation Tool** based primarily on MITRE ATT&CK.
- A way to preserve investigation context while moving across Actor / Technique / Software / Campaign and Vulnerability views.
- A way to distinguish ATT&CK direct facts from normalized environment overlap and vulnerability-only context.

### What the tool is not
- Not a CMDB or complete asset inventory.
- Not a threat-actor activity monitor or current-activity feed.
- Not an attack-likelihood, severity or risk-scoring engine.
- Not a system that infers Actor ↔ CVE, Actor ↔ Product, or causality from shared Techniques alone.

### Product boundary
`Environment Profile` stores reusable context. `Investigation Scope` selects the subset relevant to the current question. `Investigation Result` interprets only supported overlap. `Explorer` remains the detailed ATT&CK browsing layer. `Vulnerability Intelligence` remains responsible for CVE prioritization.


## v0.7.0 Technology / Platform Investigation

Technology Entryは、単なるTechnique検索ではなく次の順序で解決する。

1. ATT&CK Technique / Softwareの明示的なEntity一致
2. 一意Entityがない場合、ATT&CK Platformの完全一致または保守的なProduct名→Platform正規化
3. Platform ResultではTechnique / Softwareのplatform metadataを直接抽出し、ActorはそれらとのATT&CK direct relationshipから閲覧用に再構成する

Platform ResultのActor件数はATT&CKのActor→Platform direct relationshipを意味しない。Platform共有だけからActor↔Product、Actor↔CVE、攻撃可能性、優先度、リスクを推定しない。


## v0.7.1 Investigation Context redesign

v0.7.1では、`Investigation Scope` と `My Environment` が混在していた設計を分離する。

### Product concept

> 特定の脅威を起点に、ATT&CK等の根拠を確認しながら、その振る舞い・関係性を理解し、調査観点と自環境を重ねて、次の調査や脆弱性対応につなげる Threat Investigation Tool。

My Environmentは必須条件ではない。Threat InvestigationはATT&CK Evidence + Investigation Lensだけで成立し、Environment Profileが存在する場合だけEnvironment Overlayを追加できる。

### Three layers

1. **Threat Evidence** — ATT&CK Entity metadata / relationship / Platform metadata。
2. **Investigation Lens** — 今回どういう観点でEvidenceを読むか。My Environmentから独立。
3. **Environment Overlay** — My Environmentとの接点を任意で重ねる追加Context。

### Investigation Lens

- `General`: テーマ絞り込みなし。
- `Virtualization`: ATT&CK Platform `ESXi` を主条件にするATT&CK-native lens。
- `Identity`, `Internet-facing`, `Server`, `Cloud`: 本ダッシュボードが定義するcurated lens。MITRE ATT&CKの正式分類ではない。

### Environment Overlay

- `Not used` が既定値。
- `All My Environment` またはSaved Environment Viewを任意で選択できる。
- Overlayが0件でもInvestigation実行をブロックしない。
- v0.6/v0.7の `peridotan-investigation-scopes-v1` は互換読み込みし、Saved Environment Viewとして `peridotan-environment-views-v1` に引き継げる。旧キーは削除しない。

### Result reading order

`Finding → Context → Evidence → Further Investigation`

- Finding: ATT&CKが対象について記録している事実。
- Context: Investigation Lensと、必要な場合だけEnvironment Overlayをまとめる補助情報。Findingより視覚優先度を下げる。
- Environment Overlay: 選択した場合だけ自環境との接点を追加表示する任意レイヤー。
- Evidence: ATT&CK / Curated Lens / Normalized overlapの境界。
- Further Investigation: 現在のInvestigation contextを維持して関連Entityへ進む。


## v0.7.2 concept alignment

The first-class Investigation Targets are Threat Actor, Software, and Technology. Technology is a user-facing resolver that may resolve to ATT&CK Technique, Software, or Platform metadata. CVE-first investigation belongs to Vulnerability Intelligence until external CTI provides explicit threat-to-CVE evidence.

Environment Overlay remains optional. Setup counts describe how many Environment Profile items are selected; they are never threat-match counts. When Overlay is not used, Results stay complete from ATT&CK Evidence + Investigation Lens and the environment section is intentionally compact.


## v0.7.14 Defensive Investigation Lenses

Threat Actor ProfileのDashboard-derived viewは `Defensive Investigation Lenses` と呼ぶ。6 Lensを固定の閲覧モデルとして定義し、該当TechniqueがあるLensだけを表示する。表示数はActorごとに0〜6で変化する。

- Entry & Preparation
- Execution & Persistence
- Identity & Privilege
- Stealth & Defense
- Discovery & Movement
- Data, C2 & Impact

LensはATT&CK Tacticそのものではなく、複数Tacticを防御側調査観点にまとめたDashboard独自表示である。Techniqueが複数Tacticに属する場合、複数Lensに現れるためLens別件数の合計はUnique Techniquesと一致しないことがある。危険度、現在活動、Control mapping、対策優先度、リスクスコアを示さない。
