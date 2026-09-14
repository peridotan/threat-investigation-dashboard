#!/usr/bin/env python3
"""Download latest MITRE ATT&CK Enterprise STIX 2.1 and build a compact cross-entity dashboard dataset."""
from __future__ import annotations

import json
import re
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parents[1] / "data" / "dashboard.json"
USER_AGENT = "peridotan-threat-actor-intelligence-dashboard/0.3.0"


def active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def extref(obj: dict) -> tuple[str, str]:
    refs = obj.get("external_references") or []
    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", ""), ref.get("url", "")
    for ref in refs:
        if ref.get("external_id"):
            return ref.get("external_id", ""), ref.get("url", "")
    return "", ""


def clean_description(text: str, limit: int = 1800) -> str:
    if not text:
        return ""
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    text = re.sub(r"\(Citation:[^\)]+\)", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def base_item(obj: dict) -> dict:
    external_id, url = extref(obj)
    return {
        "stix_id": obj.get("id", ""),
        "external_id": external_id or obj.get("id", ""),
        "name": obj.get("name", ""),
        "aliases": list(dict.fromkeys(obj.get("aliases") or [])),
        "description": clean_description(obj.get("description", "")),
        "created": obj.get("created", ""),
        "modified": obj.get("modified", ""),
        "version": obj.get("x_mitre_version", ""),
        "url": url,
    }


def fetch_bundle() -> dict:
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=90) as response:
        return json.load(response)


def main() -> None:
    bundle = fetch_bundle()
    objects = [o for o in bundle.get("objects", []) if active(o)]

    actor_objs = [o for o in objects if o.get("type") == "intrusion-set"]
    technique_objs = [o for o in objects if o.get("type") == "attack-pattern"]
    software_objs = [o for o in objects if o.get("type") in {"malware", "tool"}]
    campaign_objs = [o for o in objects if o.get("type") == "campaign"]
    relationships = [o for o in objects if o.get("type") == "relationship"]

    actor_ext = {o["id"]: extref(o)[0] or o["id"] for o in actor_objs}
    technique_ext = {o["id"]: extref(o)[0] or o["id"] for o in technique_objs}
    software_ext = {o["id"]: extref(o)[0] or o["id"] for o in software_objs}
    campaign_ext = {o["id"]: extref(o)[0] or o["id"] for o in campaign_objs}

    actor_tech = defaultdict(set)
    actor_soft = defaultdict(set)
    actor_campaign = defaultdict(set)
    tech_actors = defaultdict(set)
    tech_soft = defaultdict(set)
    tech_campaign = defaultdict(set)
    soft_actors = defaultdict(set)
    soft_tech = defaultdict(set)
    soft_campaign = defaultdict(set)
    campaign_actors = defaultdict(set)
    campaign_tech = defaultdict(set)
    campaign_soft = defaultdict(set)

    for rel in relationships:
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        relationship_type = rel.get("relationship_type")

        if relationship_type == "uses" and source in actor_ext and target in technique_ext:
            actor_tech[source].add(technique_ext[target])
            tech_actors[target].add(actor_ext[source])
        elif relationship_type == "uses" and source in actor_ext and target in software_ext:
            actor_soft[source].add(software_ext[target])
            soft_actors[target].add(actor_ext[source])
        elif relationship_type == "attributed-to" and source in campaign_ext and target in actor_ext:
            campaign_actors[source].add(actor_ext[target])
            actor_campaign[target].add(campaign_ext[source])
        elif relationship_type == "uses" and source in campaign_ext and target in technique_ext:
            campaign_tech[source].add(technique_ext[target])
            tech_campaign[target].add(campaign_ext[source])
        elif relationship_type == "uses" and source in campaign_ext and target in software_ext:
            campaign_soft[source].add(software_ext[target])
            soft_campaign[target].add(campaign_ext[source])
        elif relationship_type == "uses" and source in software_ext and target in technique_ext:
            soft_tech[source].add(technique_ext[target])
            tech_soft[target].add(software_ext[source])

    actors = []
    for o in actor_objs:
        item = base_item(o)
        item.update({
            "techniques": sorted(actor_tech[o["id"]]),
            "software": sorted(actor_soft[o["id"]]),
            "campaigns": sorted(actor_campaign[o["id"]]),
        })
        actors.append(item)

    techniques = []
    for o in technique_objs:
        item = base_item(o)
        item.update({
            "tactics": sorted({p.get("phase_name", "") for p in o.get("kill_chain_phases", []) if p.get("phase_name")}),
            "platforms": sorted(o.get("x_mitre_platforms") or []),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique", False)),
            "actors": sorted(tech_actors[o["id"]]),
            "software": sorted(tech_soft[o["id"]]),
            "campaigns": sorted(tech_campaign[o["id"]]),
        })
        techniques.append(item)

    software = []
    for o in software_objs:
        item = base_item(o)
        item.update({
            "software_type": o.get("type", "software"),
            "platforms": sorted(o.get("x_mitre_platforms") or []),
            "actors": sorted(soft_actors[o["id"]]),
            "techniques": sorted(soft_tech[o["id"]]),
            "campaigns": sorted(soft_campaign[o["id"]]),
        })
        software.append(item)

    campaigns = []
    for o in campaign_objs:
        item = base_item(o)
        item.update({
            "actors": sorted(campaign_actors[o["id"]]),
            "techniques": sorted(campaign_tech[o["id"]]),
            "software": sorted(campaign_soft[o["id"]]),
            "first_seen": o.get("first_seen", ""),
            "last_seen": o.get("last_seen", ""),
        })
        campaigns.append(item)

    actors.sort(key=lambda x: (x["name"].lower(), x["external_id"]))
    techniques.sort(key=lambda x: (x["external_id"], x["name"].lower()))
    software.sort(key=lambda x: (x["name"].lower(), x["external_id"]))
    campaigns.sort(key=lambda x: (x["name"].lower(), x["external_id"]))

    collections = [o for o in objects if o.get("type") == "x-mitre-collection" and "Enterprise" in o.get("name", "")]
    collection = collections[0] if collections else {}
    latest_modified = max((o.get("modified", "") for o in objects), default="")

    result = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "MITRE ATT&CK Enterprise STIX 2.1",
            "source_url": SOURCE_URL,
            "collection_version": collection.get("x_mitre_version", ""),
            "attack_spec_version": collection.get("x_mitre_attack_spec_version", ""),
            "latest_object_modified": latest_modified,
            "schema_version": "0.2.0",
            "placeholder": False,
            "counts": {
                "actors": len(actors),
                "techniques": len(techniques),
                "software": len(software),
                "campaigns": len(campaigns),
                "relationships": len(relationships),
            },
        },
        "actors": actors,
        "techniques": techniques,
        "software": software,
        "campaigns": campaigns,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"Wrote {OUT}")
    print(json.dumps(result["meta"]["counts"], ensure_ascii=False))


if __name__ == "__main__":
    main()
