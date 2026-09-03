"""Console entry point: ``sigil = sigil_cli.__main__:main``."""

import sys

from sigil_cli._bootstrap import BootstrapError, run


def main(argv=None):
    """Locate (or download) the Sigil binary and hand off ``argv`` to it.

    On POSIX this never returns when the hand-off succeeds (the process is
    replaced). On Windows, or when bootstrapping fails, the exit code is
    returned so ``sys.exit`` can propagate it.
    """
    if argv is None:
        argv = sys.argv[1:]
    try:
        return run(argv)
    except BootstrapError as exc:
        sys.stderr.write("sigil: %s\n" % exc)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
