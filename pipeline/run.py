"""Train on permitted historical outcomes and write all production contract artifacts."""
from pathlib import Path
import argparse
import json
import pickle
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd

from pipeline.data import ARTIFACTS, CACHE, FLAGS, manifest, training_rows, write_json
from pipeline.embed import MODEL_ID, REVISION, embeddings
from pipeline.evaluate import prepared, ranked_indices
from pipeline.features import production_allowlist, KEYWORDS, clean_description
from pipeline.models import Recipe, FittedModel

CONTRACT_COLUMNS = ['rank', 'cve_id', 'published', 'snapshot_month', 'score', 'epss', 'any_exploit',
                    *FLAGS, 'cvss3_score', 'attack_vector', 'cwe_ids', 'assigner', 'description', 'reasons']


def explanation_label(name, row, h, value):
    if name == 'epss_log':
        return 'epss', f'EPSS was {float(row.epss) if pd.notna(row.epss) else 0:.5f} at snapshot', float(row.epss) if pd.notna(row.epss) else 0.
    if name == 'epss_percentile':
        return name, f'EPSS ranked in the {value*100:.1f}th percentile of this month’s eligible pool', value
    if name in FLAGS:
        source = {'exploitdb': 'Exploit-DB', 'metasploit': 'Metasploit', 'nuclei': 'Nuclei', 'poc_github': 'GitHub'}[name]
        noun = 'Detection template' if name == 'nuclei' else 'Public exploit code'
        return name, f'{noun} {"present" if row[name] else "not recorded"} on {source} at snapshot', int(row[name])
    if name in {'any_exploit', 'exploit_count'}:
        count = int(row[FLAGS].sum())
        return name, f'{count} public exploit or detection-tool signals at snapshot', count
    if name in {'assigner_prior_kev', 'vendor_prior_kev', 'assigner_recent_kev', 'vendor_recent_kev'}:
        count = int(h[name])
        entity = 'Assigning organization' if name.startswith('assigner') else 'Vendor'
        period = ' in the preceding year' if 'recent' in name else ''
        return name, f'{entity} has {count} earlier KEV entries{period}', count
    if name == 'id_year_gap':
        return name, f'CVE identifier predates publication by {int(value)} years', int(value)
    if name == 'days_at_snapshot':
        return name, f'{int(value)} days between publication and snapshot', int(value)
    if name == 'identity_embedding':
        return name, 'IBM Granite representation of the assigning organization', str(row.assigner)
    if name == 'description_embedding':
        return name, 'IBM Granite representation of the sanitized technical description', 'sanitized description'
    if name in {'text_vendor_prior_kev', 'text_product_prior_kev', 'text_vendor_recent_kev', 'text_product_recent_kev'}:
        count = int(h[name])
        kind = 'product' if 'product' in name else 'vendor'
        identity = h[f'text_{kind}_identity'] or f'unmatched {kind}'
        period = ' in the preceding year' if 'recent' in name else ''
        return name, f'{identity} has {count} earlier KEV entries{period}', count
    if name.startswith('text_') and name[5:] in KEYWORDS:
        meanings = {'remote_code': 'remote code or command execution', 'unauthenticated': 'unauthenticated access',
                    'traversal': 'path traversal', 'deserialization': 'deserialization', 'edge_device': 'an edge device',
                    'privilege_escalation': 'privilege escalation', 'memory_corruption': 'memory corruption',
                    'sql_injection': 'SQL injection', 'xss': 'cross-site scripting', 'wordpress': 'WordPress',
                    'denial_service': 'denial of service', 'upload': 'executable file upload'}
        return name, f'Sanitized description {"mentions" if value else "does not mention"} {meanings[name[5:]]}', int(value)
    if name == 'exploit_rule_blend':
        return name, 'Contribution from the public-exploit-first ranking rule', int(row.any_exploit)
    raise ValueError(f'No plain-English explanation for {name}')


def reasons_for(rows, h, x, terms, names):
    # Sum embedding dimensions into one interpretable group; the grouping preserves log odds.
    groups = {}
    for i, name in enumerate(names):
        group = 'identity_embedding' if name.startswith('identity_emb_') else ('description_embedding' if name.startswith('description_emb_') else name)
        groups.setdefault(group, []).append(i)
    grouped = {name: terms[:, ix].sum(axis=1) for name, ix in groups.items()}
    output = []
    for pos, (idx, row) in enumerate(rows.iterrows()):
        ordered = sorted(grouped, key=lambda name: (-abs(grouped[name][pos]), name))[:5]
        reasons = []
        for name in ordered:
            value = float(x.loc[idx, name]) if name in x else 0.
            feature, label, value = explanation_label(name, row, h.loc[idx], value)
            reasons.append({'feature': feature, 'label': label, 'value': value,
                            'contribution': round(float(grouped[name][pos]), 6)})
        output.append(json.dumps(reasons, ensure_ascii=False, allow_nan=False))
    return output


def run():
    backtest = json.loads((ARTIFACTS / 'backtest.json').read_text())
    audit = json.loads((CACHE / 'leak_audit.json').read_text())
    recipe = Recipe(**json.loads((CACHE / 'selected_recipe.json').read_text()))
    assert backtest['selection']['gates'][recipe.name]['passes_all_four'], 'Submitted recipe must pass all baseline gates'
    rows, h, blocks = prepared()
    train = training_rows(rows.loc[rows.published.str[:4].isin(['2024', '2025'])], '2025-12-31')
    target = rows.loc[rows.published.str.startswith('2026')].copy()
    assert len(target) == 72670
    x = blocks[recipe.block]
    production_allowlist(x.columns, allow_text=recipe.block == 'text')
    embed = embeddings(rows, recipe.embedding) if recipe.embedding else None
    model = FittedModel(recipe).fit(x.loc[train.index], train.label, embed[train.index] if embed is not None else None)
    production_allowlist(model.columns, allow_text=recipe.block == 'text')
    probability, terms, intercept, names = model.predict(x.loc[target.index], embed[target.index] if embed is not None else None, contributions=True)
    target['score'] = probability
    rank_score = model.ranking_score(x.loc[target.index], probability)
    order = ranked_indices(target.cve_id, rank_score)
    best = target.iloc[order[:5000]].copy()
    best['rank'] = np.arange(1, 5001)
    best['reasons'] = reasons_for(best, h, x, terms[order[:5000]], names)
    best['description'] = best.description.map(clean_description)
    vendor_key = 'text_vendor_identity' if recipe.block == 'text' else 'vendor_identity'
    history_key = 'text_vendor_prior_kev' if recipe.block == 'text' else 'vendor_prior_kev'
    best['vendor_identity'] = h.loc[best.index, vendor_key]
    best['vendor_prior_kev'] = h.loc[best.index, history_key].astype(int)
    best['assigner_prior_kev'] = h.loc[best.index, 'assigner_prior_kev'].astype(int)
    best['product_identity'] = h.loc[best.index, 'text_product_identity']
    best['product_prior_kev'] = h.loc[best.index, 'text_product_prior_kev'].astype(int)
    best['entity_source'] = h.loc[best.index, 'entity_source']
    best['ranking_tier'] = best.any_exploit if recipe.tiered else 0
    best['score_horizon'] = 'later KEV inclusion; historical variable follow-up'
    best['explanation_base_log_odds'] = intercept[order[:5000]]
    best['explanation_omitted_log_odds'] = [float(terms[p].sum() - sum(r['contribution'] for r in json.loads(reason)))
                                           for p, reason in zip(order[:5000], best.reasons)]
    extras = ['vendor_identity', 'vendor_prior_kev', 'assigner_prior_kev', 'score_horizon',
              'explanation_base_log_odds', 'explanation_omitted_log_odds', 'product_identity',
              'product_prior_kev', 'entity_source', 'ranking_tier']
    best[CONTRACT_COLUMNS + extras].to_csv(ARTIFACTS / 'scores_2026_top5000.csv', index=False)
    best[['cve_id']].head(500).to_csv(ARTIFACTS / 'top500.csv', index=False)
    target[['cve_id', 'score']].iloc[order].to_parquet(CACHE / 'scores_2026_full.parquet', index=False)
    with (CACHE / 'fitted_model.pkl').open('wb') as f:
        pickle.dump(model, f)
    exclusions = audit['features_excluded'] + [
        {'name': 'unfiltered_description_and_incident_claims',
         'why': 'Explicit exploitation claims and incident reports are removed before keyword, entity and embedding features. Sanitized text is an eligible candidate under a documented residual timestamp risk.'},
        {'name': 'post_2025_exploitation_data', 'why': 'No external labels or scores used. All outcomes stop at 2025-12-31.'},
        {'name': 'target_kev_membership', 'why': 'Only used for historical eligibility/labels; never a model feature.'}]
    card = {
        'model': recipe.name, 'trained_on': '2024-published and Jan–Sep 2025-published eligible CVEs, labels observed by 2025-12-31; minimum 90 days follow-up',
        'features_used': names, 'features_excluded': exclusions,
        'ibm_technology': [f'{MODEL_ID} revision {REVISION}; sentence-transformers on Apple MPS; description and identity embedding ablations'],
        'ibm_in_selected_model': recipe.embedding or 'Evaluated in research; not selected by baseline-protection gate',
        'recipe': recipe.__dict__, 'training_pool': len(train), 'training_positives': int(train.label.sum()),
        'label': 'KEV addition after the row’s snapshot through the historical label cutoff',
        'score_interpretation': 'Estimated probability of later catalog inclusion under historical variable follow-up; not a 30-day exploitation probability.',
        'calibration': {'method': 'Unweighted binary log-loss; no class balancing, no post-hoc test-set calibration',
                        'limitation': 'Scarce positives, censored negatives, changing catalog scope and EPSS versions limit absolute probability reliability.'},
        'explanations': 'Top five grouped terms by absolute signed log-odds contribution. Base and omitted terms are supplied separately; contributions are associations, not causes.',
        'snapshot_rule': 'Use supplied scoreboard snapshot_month, including June 2026 → July. Never fetch a later signal.',
        'ranking_policy': backtest['ranking_policy'],
        'ranking_probability_note': 'For a tiered recipe, score remains the learned probability; rank enforces public-tool-first policy. Scores need only decrease within each tier. Tier priority is a policy, not a claimed log-odds effect.',
        'calendar_analog': backtest.get('exact_calendar_analog'),
        'calendar_analog_caveat': 'This additional calendar-shaped sensitivity is reported separately from the two required selection splits; the learned recipe may lose to the rule at one of its budgets.',
        'history_cutoff': 'KEV entries date_added <= snapshot end and <= 2025-12-31; 2026 history is frozen at 2025 year-end.',
        'metadata_display': ['cvss3_score', 'attack_vector', 'cwe_ids', 'description'],
        'metadata_display_note': 'Current CVSS, attack vector and CWE serve the display contract only. The CSV exports sanitized current description text; description features enter only text recipes.',
        'description_policy': {'enabled_in_selected_model': recipe.block == 'text',
                               'sanitization': 'Remove entire incident-claim sentences, then URLs, CVE identifiers and dates, before entities/keywords/embeddings.',
                               'residual_risk': 'Current technical descriptions may have changed after the snapshot. Sanitization cannot establish original wording; identity matching is heuristic.',
                               'strict_reference': 'logistic_strict and lightgbm_sparse_strict remain in every eligible split.'},
        'limitations': ['Historical labels are KEV inclusion, not first attack.', 'All-2025 results include right censoring; mature and fixed-horizon sensitivity are separate.',
                        'Model selection uses historical development splits; no untouched validation of the selected recipe.',
                        'Historical assigning-organization values are assumed stable; the source has no field-level revision history.',
                        'Sanitized description features, if selected, retain unquantifiable residual revision risk.'],
        'leak_checks': {'passed': True, **audit['checks'],
                        'train_test_cve_disjoint': True, 'training_label_cutoffs_enforced': True,
                        'baseline_protection_gate': True, 'strict_production_allowlist': recipe.block != 'text',
                        'sanitized_text_allowlist': recipe.block == 'text'},
        'input_manifest': json.loads((CACHE / 'input_manifest.json').read_text()),
        'audit_baseline': audit['baseline'],
    }
    write_json(ARTIFACTS / 'model_card.json', card)
    from pipeline.findings import run as findings
    findings()
    from pipeline.checks import artifact_checks
    artifact_checks()
    print('Production:', recipe.name, len(train), 'training rows;', int(train.label.sum()), 'positives', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--all', action='store_true', help='Rebuild embeddings, evaluation, leak audit and final artifacts')
    args = parser.parse_args()
    if args.all:
        manifest()
        # Torch/MPS and LightGBM load different native OpenMP runtimes on macOS.
        # A fresh interpreter keeps embedding generation out of the training process.
        subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('embed.py'))], check=True)
        from pipeline.evaluate import run as evaluate
        from pipeline.leak_audit import run as leak_audit
        evaluate()
        leak_audit()
        from pipeline.analog import run as analog
        analog()
    run()
