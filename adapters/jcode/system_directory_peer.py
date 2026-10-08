"""Jcode peer for XNET source/tool discovery; it executes no discovered tools."""
from xnet.system_catalog import handle_request, strict_json, verify_source
from pathlib import Path


class SystemDirectoryPeer:
    def __init__(self, directory_path, *, source_root, approved_mounts=None):
        self.path = Path(directory_path)
        self.source_root = Path(source_root)
        self.mounts = dict(approved_mounts or {})

    def discover(self, request, *, verify_selected=False):
        if self.path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('directory exceeds bound')
        result = handle_request(strict_json(self.path.read_bytes()), request)
        if verify_selected:
            result['source_checks'] = [verify_source(row,workspace_root=self.source_root,
                verify_evidence=True,mounts=self.mounts) for row in result['entries']]
        return result
