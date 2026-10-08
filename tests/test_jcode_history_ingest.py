"""Exact offline Jcode-export ingestion with the actual native gateway, zero models."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from test_native_public import BINARY as RUST
import hashlib

def pin(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

from adapters.jcode.peer import JcodeContextPeer, validate_history_export
from xnet_sdk import Client, ContextPeer, XnetError
from xnet.protocol import canonical, sha256

def fixture_export():
    body={'schema':'jcode.xnet.history-export.v1','task_id':'app-fixture','session_id':'session-fixture',
          'selected_message_ids':['m1','m2'],
          'source':{'snapshot_sha256':'1'*64,'journal_sha256':'2'*64,'snapshot_bytes':100,'journal_bytes':80},
          'records':[],'work_performed':False,'authority':'none','model_calls':0}
    for index,(role,kind,text) in enumerate([
            ('user','note','Keep café 🧬 exactly\r\n'),
            ('assistant','tool-result','{"result":"stored public fixture"}\n')]):
        identity={'task_id':body['task_id'],'session_id':body['session_id'],'message_id':f'm{index+1}','block_index':0}
        body['records'].append({'event_id':sha256(canonical(identity)),'message_id':identity['message_id'],
            'block_index':0,'role':role,'kind':kind,'text':text,'text_sha256':sha256(text.encode('utf-8')),
            'tool_use_id':'fixture-tool-1' if kind=='tool-result' else None,
            'is_error':False if kind=='tool-result' else None})
    return seal_export(body)

def seal_export(body):
    body={key:item for key,item in body.items() if key!='export_sha256'}
    return {**body,'export_sha256':sha256(canonical(body))}

@unittest.skipUnless(RUST.is_file(),'Build native XNET first')
class JcodeHistoryIngestTests(unittest.TestCase):
    def test_exact_sources_replay_and_new_snapshot_does_not_rewrite_occurrences(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            export=fixture_export();adapter=JcodeContextPeer(runtime)
            result=adapter.ingest_history_export(export,task_id='app-fixture',peer='assistant')
            self.assertEqual(len(result['events']),2)
            for supplied,admitted in zip(export['records'],result['events']):
                envelope=json.loads(runtime.fetch(admitted['event']['source_digest'])['text'])
                self.assertEqual(envelope['text'],supplied['text'])
                self.assertEqual(envelope['message_id'],supplied['message_id'])
                self.assertEqual(envelope['role'],supplied['role'])
            before=runtime.call('health')['receipt_count']
            replay=adapter.ingest_history_export(export,task_id='app-fixture',peer='assistant')
            self.assertTrue(all(row['duplicate'] for row in replay['events']))
            self.assertEqual(runtime.call('health')['receipt_count'],before)
            updated=copy.deepcopy(export);updated['source']['journal_sha256']='3'*64
            result=adapter.ingest_history_export(seal_export(updated),task_id='app-fixture',peer='assistant')
            self.assertTrue(all(row['duplicate'] for row in result['events']))
            self.assertEqual(ContextPeer(runtime,task_id='app-fixture',peer='assistant').state()['history_count'],4)
            self.assertTrue(runtime.call('verify')['ok'])

    def test_late_bad_text_is_rejected_before_any_append(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            export=fixture_export();export['records'][1]['text']='changed bytes'
            before=runtime.call('health')['receipt_count']
            with self.assertRaisesRegex(ValueError,'exact text hash'):
                JcodeContextPeer(runtime).ingest_history_export(seal_export(export),task_id='app-fixture',peer='assistant')
            self.assertEqual(runtime.call('health')['receipt_count'],before)

    def test_escaped_record_bound_is_rejected_before_any_append(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            export=fixture_export();export['records'][1]['text']='\x00'*16000
            export['records'][1]['text_sha256']=sha256(export['records'][1]['text'].encode())
            before=runtime.call('health')['receipt_count']
            with self.assertRaisesRegex(ValueError,'native source/frame bound'):
                JcodeContextPeer(runtime).ingest_history_export(seal_export(export),task_id='app-fixture',peer='assistant')
            self.assertEqual(runtime.call('health')['receipt_count'],before)

    def test_changed_existing_message_cannot_replace_source(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            export=fixture_export();adapter=JcodeContextPeer(runtime)
            first=adapter.ingest_history_export(export,task_id='app-fixture',peer='assistant')
            export['records'][0]['text']='replacement'
            export['records'][0]['text_sha256']=sha256(b'replacement')
            with self.assertRaises(XnetError):
                adapter.ingest_history_export(seal_export(export),task_id='app-fixture',peer='assistant')
            old=json.loads(runtime.fetch(first['events'][0]['event']['source_digest'])['text'])
            self.assertEqual(old['text'],'Keep café 🧬 exactly\r\n')
            self.assertTrue(runtime.call('verify')['ok'])

    def test_recovery_after_partial_batch_replays_admitted_rows(self):
        with tempfile.TemporaryDirectory() as tmp, Client(RUST,Path(tmp)/'XNET',sha256=pin(RUST)) as runtime:
            export=fixture_export();adapter=JcodeContextPeer(runtime)
            original=runtime.call
            calls=0
            def fail_once(op,**fields):
                nonlocal calls
                if op=='context_append':
                    calls+=1
                    if calls==3: raise ConnectionError('fixture transport interruption')
                return original(op,**fields)
            from unittest.mock import patch
            with patch.object(runtime,'call',side_effect=fail_once):
                with self.assertRaises(ConnectionError):
                    adapter.ingest_history_export(export,task_id='app-fixture',peer='assistant')
            result=adapter.ingest_history_export(export,task_id='app-fixture',peer='assistant')
            self.assertTrue(result['manifest']['duplicate'])
            self.assertTrue(result['events'][0]['duplicate'])
            self.assertFalse(result['events'][1]['duplicate'])
            self.assertEqual(ContextPeer(runtime,task_id='app-fixture',peer='assistant').state()['history_count'],3)

    def test_cross_task_duplicate_ids_and_authority_are_rejected(self):
        for mutate in [
                lambda e:e.update(task_id='other-task'),
                lambda e:e.update(work_performed=True),
                lambda e:e.update(authority='execute'),
                lambda e:e['records'].append(copy.deepcopy(e['records'][0])),
                lambda e:e['records'][0].update(event_id='f'*64)]:
            export=fixture_export();mutate(export)
            with self.assertRaises(ValueError): validate_history_export(seal_export(export),'app-fixture')

if __name__=='__main__': unittest.main()
