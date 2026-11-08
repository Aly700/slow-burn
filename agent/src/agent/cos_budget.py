"""Shared daily ledger using IBM COS conditional object writes, not a mounted SQLite file."""
from datetime import datetime, timezone
import json
import uuid
from urllib.parse import urlsplit

import httpx

from .budget import DailyLimit


class CosBudget:
    def __init__(self, url, limit, bearer, client=None):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname != 's3.us-south.cloud-object-storage.appdomain.cloud'
                or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port
                or len(parsed.path.strip('/').split('/')) < 2):
            raise ValueError('COS budget requires an IBM us-south bucket and object prefix')
        self.url, self.limit, self.bearer = url.rstrip('/'), max(0, int(limit)), bearer
        self.client = client or httpx.Client(timeout=8, follow_redirects=False, trust_env=False)

    def day(self):
        return datetime.now(timezone.utc).date().isoformat()

    def _request(self, method, day, **kwargs):
        headers = {'Authorization': 'Bearer '+self.bearer(), **kwargs.pop('headers', {})}
        try:
            return self.client.request(method, f'{self.url}/{day}.json', headers=headers, **kwargs)
        except httpx.HTTPError:
            raise RuntimeError('Daily token budget unavailable; showing recorded answers.') from None

    def _read(self, day):
        response = self._request('GET', day)
        if response.status_code == 404:
            return {'used': 0, 'blocked': False, 'reservations': {}}, None
        try:
            if response.status_code != 200:
                raise ValueError()
            body, etag = response.json(), response.headers['etag']
            if type(body['used']) is not int or body['used'] < 0 or type(body['blocked']) is not bool or not isinstance(body['reservations'], dict):
                raise ValueError()
            return body, etag
        except (ValueError, TypeError, KeyError):
            raise RuntimeError('Daily token budget unavailable; showing recorded answers.') from None

    def _change(self, day, change):
        for _ in range(8):
            body, etag = self._read(day)
            result = change(body)
            headers = {'If-Match': etag} if etag else {'If-None-Match': '*'}
            response = self._request('PUT', day, content=json.dumps(body).encode(), headers={**headers, 'Content-Type': 'application/json'})
            if response.status_code in {200, 201}:
                return result
            if response.status_code not in {409, 412}:
                break
        raise RuntimeError('Daily token budget unavailable; showing recorded answers.')

    def status(self):
        day = self.day()
        body, _ = self._read(day)
        return {'day':day, 'limit_tokens':self.limit, 'used_tokens':body['used'],
                'remaining_tokens':max(0, self.limit-body['used']), 'exhausted':body['blocked'] or body['used'] >= self.limit}

    def reserve(self, amount):
        if amount < 0:
            raise ValueError('invalid token reservation')
        day, rid = self.day(), uuid.uuid4().hex
        def change(body):
            if body['blocked'] or body['used']+amount > self.limit:
                body['blocked'] = True
                return False
            body['used'] += amount
            body['reservations'][rid] = amount
            return True
        if not self._change(day, change):
            raise DailyLimit()
        return day+'/'+rid

    def settle(self, receipt, actual):
        if actual < 0:
            raise ValueError('invalid token usage')
        day, rid = receipt.split('/')
        def change(body):
            reserved = body['reservations'].pop(rid, None)
            if reserved is not None:
                body['used'] += actual-reserved
                body['blocked'] |= actual > reserved
        self._change(day, change)

    def close(self):
        self.client.close()
