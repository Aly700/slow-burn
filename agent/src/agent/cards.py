from datetime import datetime

from .evidence import resolve
from .narrative import describe, description_ref

# These fixed templates remain the archived reasons-only comparison's prose.
ACTIONS = {
    'remediate': 'Confirm the affected product and installed version, then prioritize the vendor-supported fix through the emergency change process. If a fix cannot be applied, restrict reachable attack paths and verify the control with the service owner.',
    'investigate': 'Confirm product, version and exposure with the service owner. Review the vendor\'s remediation guidance, schedule a tested fix if affected, and monitor the snapshot signals for change.',
    'monitor': 'Check whether the affected product is deployed and record the exposure decision. Keep the item in the normal patch queue and reassess when exploit signals or exposure change.',
}
HEADLINES = {'fix_now':'Prioritize remediation review for', 'watch':'Check exposure and plan remediation for', 'defer':'Keep under routine review:'}


def month_label(month):
    return datetime.strptime(month, '%Y-%m').strftime('%B %Y')


def percent(value):
    decimals = 1 if value >= .01 else 2 if value >= .0001 else 4
    return f'{value*100:.{decimals}f}%'


def evidence_cards(calls):
    cards = []
    for call in calls:
        name, out = call['tool'], call['output']
        def add(text, fields=(), category='signal', refs=()):
            evidence = [{'tool':name,'field':field,'value':resolve(out,field),'call_id':call['call_id']} for field in fields]
            cards.append({'id':f'f{len(cards)+1}', 'text':text, 'evidence':evidence+list(refs), 'category':category})
        if name == 'get_cve':
            profile = describe(out)
            if profile['product']:
                add(f"Affected product or component named in the supplied description: {profile['product']['text']}.", category='product', refs=[description_ref(call,profile['product'])])
            if profile['service_class']:
                s = profile['service_class']
                article = 'an' if s['label'][0].lower() in 'aeiou' else 'a'
                add(f"The description identifies {article} {s['label']} component (“{s['text']}”), a class to check for internet exposure; actual deployment reachability still needs confirmation.", category='exposure', refs=[description_ref(call,s)])
            if profile['impact']:
                add(f"The supplied description states the attacker capability or prerequisite: “{profile['impact']['text']}”", category='impact', refs=[description_ref(call,profile['impact'])])
            if profile['patch']:
                add(f"The supplied description names remediation: “{profile['patch']['text']}” Confirm the installed release and applicable branch before changing it.", category='remediation', refs=[description_ref(call,profile['patch'])])
            month = month_label(out['snapshot_month'])
            epss = out['signals']['epss']
            if epss is not None:
                add(f'EPSS put the chance of attack in the next 30 days at {percent(epss)} at the end of {month}.', ['snapshot_month','signals.epss'])
            flags = {'exploitdb':'Exploit-DB exploit code','metasploit':'a Metasploit module','nuclei':'a Nuclei scanner template','poc_github':'a GitHub proof of concept'}
            present = [key for key in flags if out['signals'].get(key) == 1]
            if present:
                add(f"By the end of {month}, public material was available as {', '.join(flags[k] for k in present)}. This is a readiness signal, not confirmation of attacks.", ['snapshot_month']+[f'signals.{k}' for k in present])
            elif all(out['signals'].get(k) == 0 for k in flags):
                add(f'No Exploit-DB, Metasploit, Nuclei or GitHub public-material signal was recorded at the end of {month}; absence of a signal does not establish safety.', ['snapshot_month']+[f'signals.{k}' for k in flags])
            if not out['signals_available']:
                add(f'The supplied files have no signal observation for {month}; missing evidence is unknown.', ['snapshot_month','signals_available'], 'limitation')
        elif name == 'vendor_history':
            if out['prior_kev']:
                latest = f"{out['latest_cve']} on {out['last_added']}" if out.get('latest_cve') else out['last_added']
                fields = ['vendor','prior_kev','catalog_cutoff','last_added','match_method'] + (['latest_cve'] if out.get('latest_cve') else [])
                add(f"{out['vendor']} has {out['prior_kev']} earlier confirmed-exploitation entries through {out['catalog_cutoff']}; the latest was {latest}. The count uses exact normalized vendor-name matching.", fields, 'history')
            else:
                add(f"No earlier KEV entry matched the vendor name {out['vendor']} through {out['catalog_cutoff']}; aliases and acquisitions are not resolved, so this does not establish a clean history.", ['vendor','prior_kev','catalog_cutoff','match_method'], 'history')
            if out['ransomware_known']:
                add(f"Of those vendor entries, {out['ransomware_known']} were marked as used in ransomware in the {out['ransomware_known_as_of']} catalog.", ['ransomware_known','ransomware_known_as_of'], 'history')
        elif name == 'similar_exploited' and out['matches']:
            m = out['matches'][0]
            fields = ['matches.0.cve_id','matches.0.date_added','matches.0.similarity','embedding_model']
            context = ''
            if m.get('vendor') and m.get('product'):
                context = f" ({m['vendor']} {m['product']})"
                fields += ['matches.0.vendor','matches.0.product']
            add(f"The closest previously exploited description is {m['cve_id']}{context}, added to KEV on {m['date_added']} (Granite cosine similarity {m['similarity']:.3f}). This analogy does not prove the candidate was exploited or affects the same product.", fields, 'analogy')
        elif name == 'signal_timeline':
            if out['missing_months']:
                add(f"Signal history is missing {len(out['missing_months'])} month(s) through {month_label(out['snapshot_month'])}; do not interpret those gaps as zero risk.", ['missing_months','snapshot_month'], 'limitation')
            if len(out['months']) >= 2:
                first,last = out['months'][0],out['months'][-1]
                if first['epss'] is not None and last['epss'] is not None:
                    add(f"EPSS estimated {percent(first['epss'])} at the end of {month_label(first['month'])} and {percent(last['epss'])} at the end of {month_label(last['month'])}; the March 2025 model change limits comparisons across that date.", ['months.0.month','months.0.epss',f"months.{len(out['months'])-1}.month",f"months.{len(out['months'])-1}.epss",'warnings.1'], 'timeline')
    return cards
