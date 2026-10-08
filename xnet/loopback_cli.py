"""Explicit entry points for Loopback; no background work at import."""
import argparse
from pathlib import Path
import sys


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog='xnet loopback')
    parser.add_argument('component', choices=('index', 'catalog', 'feed'))
    if not values or values[0] in {'-h', '--help'}:
        parser.print_help()
        return 0
    args = parser.parse_args(values[:1])
    rest = values[1:]
    if args.component == 'index':
        from adapters.loopback.cli import main as index_main
        return index_main(rest)
    if args.component == 'catalog':
        from .system_catalog import main as catalog_main
        if '--directory' not in rest:
            rest = ['--directory', str(Path(__file__).parent / 'data/system-directory.json'), *rest]
        return catalog_main(rest)
    from adapters.loopback.feed_engine import main as feed_main
    return feed_main(rest)


if __name__ == '__main__':
    raise SystemExit(main())
