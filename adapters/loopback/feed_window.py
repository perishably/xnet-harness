"""Explicit practice-feed admission into a caller-owned hot source window."""
from pathlib import Path
from .stream_index import MetadataIndex, ReadOnlyMount, IndexErrorClosed, digest, sha256, strict_json


class PracticeFeedWindow:
    def __init__(self, root, *, generation_path, expected_generation_sha256,
                 expected_upstream_head, archive_root):
        path=Path(generation_path)
        if path.stat().st_size>512*1024:
            raise IndexErrorClosed('practice generation exceeds bound')
        raw=path.read_bytes()
        if sha256(raw)!=expected_generation_sha256:
            raise IndexErrorClosed('practice generation pin differs')
        value=strict_json(raw)
        fields={'schema','generation','provenance_class','authority','upstream_ledger_head','descriptors'}
        if type(value) is not dict or set(value)!=fields or \
                value['schema']!='xnet.public-code-feed.projection-set.v1' or \
                value['provenance_class']!='practice-stream' or value['authority']!='none' or \
                value['upstream_ledger_head']!=expected_upstream_head:
            raise IndexErrorClosed('caller-pinned practice generation required')
        rows=value['descriptors']
        if type(rows) is not list or not 1<=len(rows)<=160:
            raise IndexErrorClosed('bounded nonempty practice descriptors required')
        self.index=MetadataIndex(root,adapters={'archive-d':ReadOnlyMount(archive_root,tier='warm')},
            scope_id='practice-stream-r01',task_id='practice',mode='practice')
        try:
            for row in rows:
                if row.get('provenance')!='practice-stream' or row.get('adapter')!='archive-d' or \
                        'partial-patch' not in row.get('tags',[]):
                    raise IndexErrorClosed('only explicit partial practice patches admitted')
                self.index.ingest(row,expected_metadata_sha256=digest(row))
        except BaseException:
            self.index.close();raise
        self.generation_pin=expected_generation_sha256
        self.head=expected_upstream_head

    def prewarm(self, trigger, *, repo, revision, cancelled=lambda:False):
        proposal=self.index.propose_prefetch(trigger,repo=repo,revision=revision,limit=3)
        return self.index.prefetch(proposal,cancelled=cancelled,max_chunks_per_source=3)

    def context(self, question, *, repo, revision, budget_bytes=2048):
        result=self.index.source_slices(question,repo=repo,revision=revision,
                                        budget_bytes=budget_bytes,max_items=4)
        return {**result,'practice_generation_sha256':self.generation_pin,
            'upstream_head_at_projection':self.head,
            'source_kind':'partial upstream patch snippets; not complete repository files',
            'promotion_authority':False,'evaluation_admission':False}

    def close(self):
        self.index.close()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()
