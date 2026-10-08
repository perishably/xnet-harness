"""Jcode context adapter: emits exact source records, never performs model work."""
from __future__ import annotations
import hashlib
import re
from xnet_sdk import Client, ContextPeer
from xnet_sdk.client import API, MAX_FRAME
from xnet.protocol import canonical, sha256

_ID=re.compile(r'[A-Za-z0-9_-]{1,128}')
_HEX=re.compile(r'[0-9a-f]{64}')

def validate_history_export(value, task_id):
    """Verify bounded data from Jcode's offline export; no execution or authority."""
    fields={'schema','task_id','session_id','selected_message_ids','source','records',
            'work_performed','authority','model_calls','export_sha256'}
    if type(value) is not dict or set(value)!=fields:
        raise ValueError('invalid Jcode history export fields')
    if (value['schema']!='jcode.xnet.history-export.v1' or value['task_id']!=task_id
        or value['work_performed'] is not False or value['authority']!='none'
        or type(value['model_calls']) is not int or value['model_calls']!=0):
        raise ValueError('Jcode export task or source-only contract mismatch')
    for key in ('task_id','session_id'):
        if type(value[key]) is not str or not _ID.fullmatch(value[key]):
            raise ValueError('invalid Jcode export ID')
    def pin(value):
        return type(value) is str and _HEX.fullmatch(value) is not None
    def uint(value):
        return type(value) is int and 0<=value<=2**63-1
    selected=value['selected_message_ids']
    if (type(selected) is not list or not 1<=len(selected)<=32
        or any(type(item) is not str or not _ID.fullmatch(item) for item in selected)
        or len(set(selected))!=len(selected)):
        raise ValueError('invalid Jcode selected messages')
    source=value['source']
    if (type(source) is not dict or set(source)!={'snapshot_sha256','journal_sha256','snapshot_bytes','journal_bytes'}
        or not pin(source['snapshot_sha256']) or not uint(source['snapshot_bytes'])
        or not uint(source['journal_bytes']) or not 0<source['snapshot_bytes']<=16*1024*1024
        or source['journal_bytes']>16*1024*1024
        or (source['journal_sha256'] is None and source['journal_bytes']!=0)
        or (source['journal_sha256'] is not None and not pin(source['journal_sha256']))):
        raise ValueError('invalid Jcode stored source declaration')
    records=value['records']
    if type(records) is not list or not 1<=len(records)<=128:
        raise ValueError('invalid Jcode exported records')
    expected_fields={'event_id','message_id','block_index','role','kind','text','text_sha256','tool_use_id','is_error'}
    seen=set();messages=set()
    for record in records:
        if type(record) is not dict or set(record)!=expected_fields:
            raise ValueError('invalid Jcode record fields')
        if (record['message_id'] not in selected or not uint(record['block_index'])
            or record['role'] not in ('user','assistant') or record['kind'] not in ('note','tool-result')
            or type(record['text']) is not str or len(record['text'].encode('utf-8'))>61440
            or not pin(record['text_sha256']) or sha256(record['text'].encode('utf-8'))!=record['text_sha256']):
            raise ValueError('invalid Jcode record or exact text hash')
        identity={key:value[key] for key in ('task_id','session_id')}
        identity.update({key:record[key] for key in ('message_id','block_index')})
        if record['event_id']!=sha256(canonical(identity)) or record['event_id'] in seen:
            raise ValueError('changed or duplicate Jcode occurrence ID')
        if record['kind']=='note':
            if record['tool_use_id'] is not None or record['is_error'] is not None:
                raise ValueError('note cannot declare a tool result')
        elif (type(record['tool_use_id']) is not str or not record['tool_use_id']
              or len(record['tool_use_id'].encode('utf-8'))>1024
              or (record['is_error'] is not None and type(record['is_error']) is not bool)):
            raise ValueError('invalid Jcode tool result declaration')
        seen.add(record['event_id']);messages.add(record['message_id'])
    if messages!=set(selected):
        raise ValueError('selected message has no exported text')
    body={key:item for key,item in value.items() if key!='export_sha256'}
    encoded=canonical(body)
    if not pin(value['export_sha256']) or sha256(encoded)!=value['export_sha256'] or len(canonical(value))>MAX_FRAME:
        raise ValueError('Jcode export digest or frame bound mismatch')
    return body

class JcodeContextPeer:
    def __init__(self, xnet: Client):
        self.xnet = xnet  # borrowed; Jcode disconnect does not close the runtime

    def pass_notes(self, notes: list[tuple[str, str]], *, max_bytes: int = 8192):
        records = [{"id": hashlib.sha256(text.encode("utf-8")).hexdigest(), "kind": kind, "text": text} for kind, text in notes]
        return self.xnet.pack_context(records, max_bytes=max_bytes)

    def record_notes(self, task_id, peer, event_prefix, notes: list[tuple[str, str]]):
        """Record explicitly supplied Jcode notes in shared history, no global capture.

        Repeat the same prefix/list after a lost response to replay each event;
        changing an existing event's bytes is rejected by the native gateway.
        """
        context=ContextPeer(self.xnet,task_id=task_id,peer=peer)
        return [context.append(f'{event_prefix}-{index}',text,kind=kind)
                for index,(kind,text) in enumerate(notes)]

    def ingest_history_export(self, value, *, task_id, peer):
        """Pass selected stored Jcode text into a borrowed native gateway.

        Validate every supplied row before append. The batch is resumable, not
        atomic: a later native conflict/barrier can leave a staging manifest and
        earlier admitted rows. Repeating identical data replays those rows.
        Export hashes and role labels are provenance declarations, not permission.
        """
        body=validate_history_export(value,task_id)
        context=ContextPeer(self.xnet,task_id=task_id,peer=peer)
        rows=[]
        for record in body['records']:
            envelope={'schema':'xnet.jcode.stored-record.v1','task_id':task_id,
                      'session_id':body['session_id'],**record}
            text=canonical(envelope).decode('utf-8')
            request={'api':API,'id':'0'*32,'request':{
                'op':'context_append','task_id':task_id,'peer':peer,'event_id':record['event_id'],
                'kind':'raw','text':text,'expected_head':'0'*64}}
            if len(text.encode('utf-8'))>65536 or len(canonical(request))>MAX_FRAME:
                raise ValueError('exact stored record exceeds native source/frame bound')
            rows.append((record['event_id'],text))
        manifest={key:item for key,item in body.items() if key!='records'}
        manifest.update(schema='xnet.jcode.export-manifest.v1',export_sha256=value['export_sha256'],
                        record_ids=[record['event_id'] for record in body['records']],
                        record_text_sha256=[record['text_sha256'] for record in body['records']])
        admitted=context.append('jcode-export-'+value['export_sha256'],canonical(manifest).decode('utf-8'))
        events=[context.append(event_id,text,kind='raw') for event_id,text in rows]
        return {'schema':'xnet.jcode.export-ingest.v1','task_id':task_id,
                'export_sha256':value['export_sha256'],'manifest':admitted,'events':events,
                'work_performed':False,'authority':'none'}
