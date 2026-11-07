"""Display-only enforcement of the public repository naming policy."""
import hashlib
import re

from pipeline.features import KEYWORDS

# Digests keep prohibited publication terms out of the public source itself.
# This filter never runs on model inputs or changes a ranking.
BLOCKED_DIGESTS = {
    '0143cd87c1e8af412860b3ff954ad0397371df07d2f91b79d99c90ef901290f7',
    '31a85e22a24a7a4fba06c2c64be937d96cf5871f0e027919dd6b24fe4b764705',
    '53beb385cf69a2c6c9d58738452aea03672bfd803fba2c357497e1c5ad5b27b4',
    '57de4cf40144bdf7d00010f2f5557a7d642c2b9705309bfade167dd313e2ca93',
    '60965168ce762e949600281ba6d01fee136e5b6e8257b1f216f9025ed324474c',
    '62f8e1ec095e1857446d403d1431007de8813aea9553a56ccd4552a131b1f297',
    '7c38d5864015fc722b62d2f5b8cf69be50bcea73de4cfb745c8b9780e9e8d9f5',
    '7d5afabfb05077c681959869bc235ce2764e95b1f43f20d149a4939b7997e95f',
    '96a4bc2602655473120fcc571ee3d8cfe5f8801f8038ccc06323d305e323331c',
    'c0698cc6c4dbfdb1acba575bc637999e755f6f1d6fa8c68fd7cba12785ed5132',
    'c5f9d8f01eaaecc599699fbc9ada0dd9c4da6a59258bc55d6e464373afc049d5',
    'c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d',
    'fafff6df80ac162a1fcd273d2b841e8de2a9af1fd3e2e5092380a0b389e3d68b',
}


def display_description(text, blocked=BLOCKED_DIGESTS):
    words = re.findall(r'[a-z]+', text.lower())
    matches = any(hashlib.sha256(' '.join(words[i:i+n]).encode()).hexdigest() in blocked
                  for n in [1, 2, 3] for i in range(len(words)-n+1))
    if not matches:
        return text, 'sanitized description'
    mechanisms = [name.replace('_', ' ') for name, pattern in KEYWORDS.items()
                  if re.search(pattern, text, flags=re.I)]
    summary = '; '.join(mechanisms) or 'software vulnerability; detailed mechanism unavailable in this export'
    return 'Technical summary: ' + summary + '.', 'technical feature summary'
