#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "data" / "dashboard.json"


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def subset(values, allowed, label):
    unknown = set(values or []) - allowed
    if unknown:
        fail(f"unknown {label}: {sorted(unknown)[:5]}")


def main() -> None:
    data = json.loads(PATH.read_text(encoding="utf-8"))
    for key in ("meta", "actors", "techniques", "software", "campaigns"):
        if key not in data:
            fail(f"missing key: {key}")
    if data["meta"].get("placeholder"):
        fail("placeholder dataset cannot be deployed")
    if not data["actors"] or not data["techniques"]:
        fail("actors/techniques must not be empty")

    ids = {}
    for view in ("actors", "techniques", "software", "campaigns"):
        values = [x.get("external_id") for x in data[view]]
        if any(not x for x in values):
            fail(f"empty external_id in {view}")
        if len(values) != len(set(values)):
            fail(f"duplicate external_id in {view}")
        ids[view] = set(values)

    for actor in data["actors"]:
        subset(actor.get("techniques"), ids["techniques"], f"technique on {actor['external_id']}")
        subset(actor.get("software"), ids["software"], f"software on {actor['external_id']}")
        subset(actor.get("campaigns"), ids["campaigns"], f"campaign on {actor['external_id']}")

    for technique in data["techniques"]:
        subset(technique.get("actors"), ids["actors"], f"actor on {technique['external_id']}")
        subset(technique.get("software"), ids["software"], f"software on {technique['external_id']}")
        subset(technique.get("campaigns"), ids["campaigns"], f"campaign on {technique['external_id']}")

    for software in data["software"]:
        subset(software.get("actors"), ids["actors"], f"actor on {software['external_id']}")
        subset(software.get("techniques"), ids["techniques"], f"technique on {software['external_id']}")
        subset(software.get("campaigns"), ids["campaigns"], f"campaign on {software['external_id']}")

    for campaign in data["campaigns"]:
        subset(campaign.get("actors"), ids["actors"], f"actor on {campaign['external_id']}")
        subset(campaign.get("techniques"), ids["techniques"], f"technique on {campaign['external_id']}")
        subset(campaign.get("software"), ids["software"], f"software on {campaign['external_id']}")

    # Reverse relationship consistency for the v0.2 cross-entity explorer.
    actor_by_id = {x["external_id"]: x for x in data["actors"]}
    technique_by_id = {x["external_id"]: x for x in data["techniques"]}
    software_by_id = {x["external_id"]: x for x in data["software"]}
    campaign_by_id = {x["external_id"]: x for x in data["campaigns"]}

    for actor in data["actors"]:
        aid = actor["external_id"]
        for tid in actor.get("techniques", []):
            if aid not in technique_by_id[tid].get("actors", []):
                fail(f"reverse actor/technique mismatch: {aid} -> {tid}")
        for sid in actor.get("software", []):
            if aid not in software_by_id[sid].get("actors", []):
                fail(f"reverse actor/software mismatch: {aid} -> {sid}")
        for cid in actor.get("campaigns", []):
            if aid not in campaign_by_id[cid].get("actors", []):
                fail(f"reverse actor/campaign mismatch: {aid} -> {cid}")

    for technique in data["techniques"]:
        tid = technique["external_id"]
        for aid in technique.get("actors", []):
            if tid not in actor_by_id[aid].get("techniques", []):
                fail(f"reverse technique/actor mismatch: {tid} -> {aid}")
        for sid in technique.get("software", []):
            if tid not in software_by_id[sid].get("techniques", []):
                fail(f"reverse technique/software mismatch: {tid} -> {sid}")
        for cid in technique.get("campaigns", []):
            if tid not in campaign_by_id[cid].get("techniques", []):
                fail(f"reverse technique/campaign mismatch: {tid} -> {cid}")

    for software in data["software"]:
        sid = software["external_id"]
        for aid in software.get("actors", []):
            if sid not in actor_by_id[aid].get("software", []):
                fail(f"reverse software/actor mismatch: {sid} -> {aid}")
        for tid in software.get("techniques", []):
            if sid not in technique_by_id[tid].get("software", []):
                fail(f"reverse software/technique mismatch: {sid} -> {tid}")
        for cid in software.get("campaigns", []):
            if sid not in campaign_by_id[cid].get("software", []):
                fail(f"reverse software/campaign mismatch: {sid} -> {cid}")

    for campaign in data["campaigns"]:
        cid = campaign["external_id"]
        for aid in campaign.get("actors", []):
            if cid not in actor_by_id[aid].get("campaigns", []):
                fail(f"reverse campaign/actor mismatch: {cid} -> {aid}")
        for tid in campaign.get("techniques", []):
            if cid not in technique_by_id[tid].get("campaigns", []):
                fail(f"reverse campaign/technique mismatch: {cid} -> {tid}")
        for sid in campaign.get("software", []):
            if cid not in software_by_id[sid].get("campaigns", []):
                fail(f"reverse campaign/software mismatch: {cid} -> {sid}")

    print("Validation OK")
    print(data["meta"].get("counts", {}))


if __name__ == "__main__":
    main()
