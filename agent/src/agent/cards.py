from .evidence import resolve

ACTIONS = {
    "remediate": "Confirm the affected product and installed version, then prioritize the vendor-supported fix through the emergency change process. If a fix cannot be applied, restrict reachable attack paths and verify the control with the service owner.",
    "investigate": "Confirm product, version and exposure with the service owner. Review the vendor's remediation guidance, schedule a tested fix if affected, and monitor the snapshot signals for change.",
    "monitor": "Check whether the affected product is deployed and record the exposure decision. Keep the item in the normal patch queue and reassess when exploit signals or exposure change.",
}
HEADLINES = {"fix_now": "Prioritize remediation review for", "watch": "Check exposure and plan remediation for", "defer": "Keep under routine review:"}


def evidence_cards(calls):
    cards = []
    for call in calls:
        name, out = call["tool"], call["output"]
        def add(text, fields, category="signal"):
            refs = [{"tool": name, "field": field, "value": resolve(out, field), "call_id": call["call_id"]} for field in fields]
            cards.append({"id": f"f{len(cards)+1}", "text": text, "evidence": refs, "category": category})
        if name == "get_cve":
            month = out["snapshot_month"]
            if out["signals"]["epss"] is not None:
                add(f"At {month} month-end, EPSS was {out['signals']['epss']:.5f}.", ["snapshot_month", "signals.epss"])
            flags = {"exploitdb": "Exploit-DB public exploit", "metasploit": "Metasploit module", "nuclei": "Nuclei scanner template", "poc_github": "GitHub proof-of-concept"}
            for key, label in flags.items():
                value = out["signals"][key]
                if value is not None:
                    add(f"At {month} month-end, the {label} flag was {value}; this flag alone does not confirm exploitation.", ["snapshot_month", f"signals.{key}"])
            if not out["signals_available"]:
                add(f"The supplied signal files have no observation for {month}; missing signals are unknown.", ["snapshot_month", "signals_available"], "limitation")
            if out["cvss"].get("cvss3_score") is not None:
                add(f"The provided NVD extract lists CVSS 3 severity {out['cvss']['cvss3_score']}; its availability at the snapshot is unverified.", ["cvss.cvss3_score", "provenance.metadata"], "metadata")
            if out["cwes"]:
                add(f"The provided NVD extract lists {out['cwes'][0]['id']}: {out['cwes'][0]['name']}; this is current-extract metadata.", ["cwes.0.id", "cwes.0.name", "provenance.metadata"], "metadata")
        elif name == "explain_score":
            if out.get("rank") is not None:
                add(f"The supplied ranking places this CVE at rank {out['rank']}.", ["rank"], "ranking")
            for i, reason in enumerate(out.get("reasons", [])):
                if "feature" in reason and "value" in reason:
                    add(f"The ranking's {reason['feature']} feature has value {reason['value']}.", [f"reasons.{i}.feature", f"reasons.{i}.value"], "ranking")
            if not out.get("score_is_probability") and out.get("score") is not None:
                add(f"The seed score is {out['score']}; it is outside the probability contract and must not be read as an exploitation probability.", ["score", "score_is_probability"], "limitation")
        elif name == "vendor_history":
            add(f"Exact vendor-name matching for {out['vendor']} found {out['prior_kev']} earlier KEV entries through {out['catalog_cutoff']}.", ["vendor", "prior_kev", "catalog_cutoff", "match_method"], "history")
            if out["last_added"]:
                add(f"The latest earlier KEV addition for {out['vendor']} was {out['last_added']}.", ["vendor", "last_added"], "history")
            if out["ransomware_known"] is not None:
                add(f"Among those vendor entries, {out['ransomware_known']} had known ransomware use in the {out['ransomware_known_as_of']} catalog.", ["ransomware_known", "ransomware_known_as_of"], "history")
        elif name == "similar_exploited":
            for i, m in enumerate(out["matches"][:2]):
                add(f"Granite description retrieval matched {m['cve_id']} (cosine {m['similarity']:.3f}), added to KEV on {m['date_added']}. This is an analogy, not proof this CVE was exploited.", [f"matches.{i}.cve_id", f"matches.{i}.similarity", f"matches.{i}.date_added", "embedding_model"], "analogy")
        elif name == "signal_timeline":
            if out["missing_months"]:
                add(f"The supplied timeline lacks observations for {len(out['missing_months'])} month(s) through {out['snapshot_month']}; those months cannot be filled with zeroes.", ["missing_months", "snapshot_month"], "limitation")
            if len(out["months"]) >= 2:
                first, last = out["months"][0], out["months"][-1]
                if first["epss"] is not None and last["epss"] is not None:
                    add(f"Recorded EPSS was {first['epss']} in {first['month']} and {last['epss']} in {last['month']}. The March 2025 model change limits comparisons across that date.", ["months.0.month", "months.0.epss", f"months.{len(out['months'])-1}.month", f"months.{len(out['months'])-1}.epss", "warnings.1"], "timeline")
    return cards
