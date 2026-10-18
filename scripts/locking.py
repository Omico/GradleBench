"""One lock for every project writer, acquired before generation or preparation."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path


def project_path(root, path):
    """Reject linked children before a generator or cleaner follows them."""
    root=Path(os.path.abspath(root));path=Path(os.path.abspath(path))
    relative=path.relative_to(root)
    current=root
    for part in relative.parts:
        current=current/part
        if current.is_symlink():raise RuntimeError(f'Refuse linked project path: {current}')
    if not path.resolve().is_relative_to(root.resolve()):
        raise RuntimeError(f'Path escapes project: {path}')
    return path


@contextmanager
def benchmark_lock(root):
    with project_path(root,root / '.benchmark.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another GradleBench writer holds the project lock') from error
        yield
