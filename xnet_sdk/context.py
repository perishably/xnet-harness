"""Borrowed, task-bound context gateway. Peer labels are caller provenance only.

Several peers can borrow one Client. This does not turn private stdio into an
attachable service, authenticate a peer, or grant model/tool authority.
"""
from __future__ import annotations
import hashlib
import re

from .client import Client, XnetError

_CURRENT = object()

class ContextPeer:
    def __init__(self, client: Client, *, task_id: str, peer: str):
        if type(task_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', task_id):
            raise XnetError('invalid context task ID')
        if peer not in ('operator', 'assistant', 'peer'):
            raise XnetError('invalid declared peer')
        self.client, self.task_id, self.peer = client, task_id, peer

    def state(self):
        return self.client.call('context_state', task_id=self.task_id)

    def append(self, event_id, text, *, kind='raw', expected_head=_CURRENT):
        if expected_head is _CURRENT:
            expected_head = self.state()['history_head']
        return self.client.call('context_append', task_id=self.task_id, peer=self.peer,
                                event_id=event_id, kind=kind, text=text, expected_head=expected_head)

    def history(self, *, after=0, limit=32):
        return self.client.call('context_history', task_id=self.task_id, after=after, limit=limit)

    def fetch_event(self, event):
        # Select metadata from this task's admitted history before calling this
        # helper. Native FETCH itself is root-wide, not an access-control gate.
        text = self.client.fetch(event['source_digest'])['text']
        if hashlib.sha256(text.encode('utf-8')).hexdigest() != event['source_digest']:
            raise XnetError('raw context hash mismatch')
        return text

    def bind(self, session_id, *, model_sha256, runner_sha256, window, reserve):
        return self.client.call('context_bind', task_id=self.task_id, peer=self.peer,
                                session_id=session_id, model_sha256=model_sha256,
                                runner_sha256=runner_sha256, window=window, reserve=reserve)

    def occupancy(self, session_id, *, revision, used, prompt_sha256):
        return self.client.call('context_occupancy', task_id=self.task_id, peer=self.peer,
                                session_id=session_id, revision=revision, used=used,
                                prompt_sha256=prompt_sha256)

    def prepare(self, session_id, *, required_ids, max_bytes=8192, expected_head=_CURRENT):
        if expected_head is _CURRENT:
            expected_head = self.state()['history_head']
        return self.client.call('context_prepare', task_id=self.task_id, peer=self.peer,
                                session_id=session_id, expected_head=expected_head,
                                required_ids=required_ids, max_bytes=max_bytes)

    def acknowledge(self, *, plan_id, new_session_id, capsule_digest, prompt_sha256, used):
        return self.client.call('context_acknowledge', task_id=self.task_id, peer=self.peer,
                                plan_id=plan_id, new_session_id=new_session_id,
                                capsule_digest=capsule_digest, prompt_sha256=prompt_sha256, used=used)
