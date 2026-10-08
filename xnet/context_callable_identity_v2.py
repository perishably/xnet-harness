"""Scoped, source-pinned callable identity v2; immutable CodeType semantics.

marshal's reference flags vary when live packets retain a code constant. The
versioned comparison binds semantic code fields instead; source-file and policy
artifact checks remain mandatory. No old source file is changed by installation.
"""
from __future__ import annotations

import os
from pathlib import Path
import types

from xnet.protocol import canonical, sha256
from xnet.relay_log import _no_links

VERSION = 'xnet.context-callable-identity.v2'
ORIGINAL_PINS = {
    'repair_loop.py': '7b4c154b8abfc19cb8b1a1bdcb8eee196a73129f29c264207899d49c65fef5ac',
    'scaffold_context.py': '7a3557b8e4d650333a20bde810ad064d0821cd4ba7d88b94419bacedfd702b00',
    'procedural_memory.py': '01b3a2175763c42b7814a444be8e130a6b2906216f168007d063579b662fcf42',
}
_INSTALLED = None


def constant(value):
    if value is None: return ['none']
    if value is Ellipsis: return ['ellipsis']
    if type(value) is bool: return ['bool', value]
    if type(value) is int: return ['int', str(value)]
    if type(value) is str: return ['str', value]
    if type(value) is bytes: return ['bytes', value.hex()]
    if type(value) is float: return ['float', value.hex()]
    if type(value) is complex: return ['complex', value.real.hex(), value.imag.hex()]
    if type(value) is tuple: return ['tuple', [constant(item) for item in value]]
    if type(value) is frozenset:
        return ['frozenset', sorted((constant(item) for item in value), key=canonical)]
    if type(value) is types.CodeType: return ['code', code_fields(value)]
    raise ValueError('unsupported code constant; identity fails closed')


def code_fields(code):
    if type(code) is not types.CodeType: raise ValueError('exact CodeType required')
    integers = ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
                'co_stacksize', 'co_flags', 'co_firstlineno')
    strings = ('co_filename', 'co_name', 'co_qualname')
    arrays = ('co_names', 'co_varnames', 'co_freevars', 'co_cellvars')
    byte_arrays = ('co_code', 'co_linetable', 'co_exceptiontable')
    return {**{name: getattr(code, name) for name in integers + strings},
            **{name: list(getattr(code, name)) for name in arrays},
            **{name: getattr(code, name).hex() for name in byte_arrays},
            'co_consts': [constant(value) for value in code.co_consts]}


def code_sha256(code):
    return sha256(canonical({'schema': VERSION, 'code': code_fields(code)}))


def artifact():
    path = Path(__file__).absolute(); _no_links(path, regular_file=True)
    return {'path': str(path), 'sha256': sha256(path.read_bytes())}


def policy(value):
    """The installer itself must be selected by every context policy."""
    import copy
    result = copy.deepcopy(value); row = artifact()
    rows = {os.path.normcase(item['path']): item for item in result['preparer_artifacts']}
    key = os.path.normcase(row['path'])
    if key in rows and rows[key] != row: raise ValueError('identity-v2 helper source changed')
    rows[key] = row
    if len(rows) > 16: raise ValueError('identity-v2 policy exceeds existing artifact bound')
    result['preparer_artifacts'] = list(rows.values())
    return result


def context_callable_identity_v2(preparer, selected_policy):
    function = getattr(preparer, '__func__', preparer)
    if not isinstance(function, types.FunctionType): raise ValueError('source-pinned Python callback required')
    path = os.path.abspath(function.__code__.co_filename)
    selected = {os.path.normcase(row['path']): row for row in selected_policy['preparer_artifacts']}
    own = artifact()
    if selected.get(os.path.normcase(own['path'])) != own:
        raise ValueError('identity-v2 helper absent from selected source pins')
    row = selected.get(os.path.normcase(path))
    if row is None: raise ValueError('context callback source absent from selected policy')
    _no_links(Path(path), regular_file=True)
    if sha256(Path(path).read_bytes()) != row['sha256']: raise ValueError('selected callback source changed')
    if _INSTALLED is None: raise ValueError('identity-v2 not installed in this comparison process')
    return {'module': function.__module__, 'qualname': function.__qualname__, 'artifact_path': path,
            'code_sha256': code_sha256(function.__code__), 'identity_schema': VERSION}


def install():
    """Only replace three explicitly pinned comparison-process hook references."""
    global _INSTALLED
    from xnet import repair_loop, scaffold_context, procedural_memory
    modules = (repair_loop, scaffold_context, procedural_memory)
    for module in modules:
        path = Path(module.__file__); _no_links(path, regular_file=True)
        if sha256(path.read_bytes()) != ORIGINAL_PINS[path.name]:
            raise ValueError('identity-v2 original source differs; select a new adapter version')
    if _INSTALLED is not None:
        if (repair_loop._public_context_callable is not context_callable_identity_v2
            or scaffold_context._public_context_callable is not context_callable_identity_v2
            or _INSTALLED['adapter'] != artifact()):
            raise ValueError('installed identity-v2 hook or source changed')
        return dict(_INSTALLED)
    original = repair_loop._public_context_callable
    if (scaffold_context._public_context_callable is not original
        or original.__module__ != 'xnet.repair_loop' or original.__name__ != '_public_context_callable'):
        raise ValueError('original context identity hook differs')
    _INSTALLED = {'schema': VERSION, 'adapter': artifact(), 'original_source_pins': ORIGINAL_PINS.copy(),
                  'original_code_sha256_v2': code_sha256(original.__code__),
                  'disk_source_modified': False, 'accept_legacy_identity': False}
    repair_loop._public_context_callable = context_callable_identity_v2
    scaffold_context._public_context_callable = context_callable_identity_v2
    # ProceduralContextPreparer imports this exact hook dynamically from
    # repair_loop at construction/dispatch. No unrelated globals are rebound.
    return dict(_INSTALLED)
