"""Pure-Python drop-in replacement for pytest.

Enables running all tests (`python3 -m pytest tests/` or `npm test`) using only
the Python 3 standard library with zero third-party dependencies.
"""
from __future__ import annotations

import importlib.util
import inspect
import math
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
import types
from typing import Any, Callable, Dict, List, Optional, Tuple

# Guarantee single module instance across `python -m pytest` and `import pytest`
sys.modules["pytest"] = sys.modules[__name__]


class SkipException(Exception):
    pass


class raises:
    """Context manager asserting that an exception was raised."""

    def __init__(self, expected_exception, match=None):
        self.expected_exception = expected_exception
        self.match = match
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"DID NOT RAISE {self.expected_exception}")
        if not issubclass(exc_type, self.expected_exception):
            return False
        self.value = exc_val
        if self.match:
            pattern = re.compile(self.match)
            if not pattern.search(str(exc_val)):
                raise AssertionError(
                    f"Pattern {self.match!r} not found in {str(exc_val)!r}"
                )
        return True


class approx:
    """Approximate comparison helper for floating-point values."""

    def __init__(self, expected, rel=1e-6, abs=1e-12):
        self.expected = expected
        self.rel = rel
        self.abs = abs

    def __eq__(self, actual):
        if isinstance(self.expected, (int, float)) and isinstance(actual, (int, float)):
            diff = abs(self.expected - actual)
            tol = max(self.abs, self.rel * abs(self.expected))
            return diff <= tol
        return actual == self.expected

    def __repr__(self):
        return f"approx({self.expected} \u00b1 {self.rel * abs(self.expected)})"


def skip(reason: str = ""):
    raise SkipException(reason)


def fail(reason: str = ""):
    raise AssertionError(reason)


_GLOBAL_FIXTURES: Dict[str, Callable] = {}


def fixture(scope: str = "function", **kwargs):
    def decorator(fn):
        fn._is_pytest_fixture = True
        _GLOBAL_FIXTURES[fn.__name__] = fn
        return fn
    if callable(scope):
        fn = scope
        fn._is_pytest_fixture = True
        _GLOBAL_FIXTURES[fn.__name__] = fn
        return fn
    return decorator


class MarkHelper:
    def __getattr__(self, name):
        def mark_decorator(*args, **kwargs):
            if name == "skipif":
                condition = args[0] if args else True
                reason = kwargs.get("reason", "")
                def inner(fn):
                    setattr(fn, "_pytest_skipif", (condition, reason))
                    return fn
                return inner
            elif name == "skip":
                reason = args[0] if args else kwargs.get("reason", "")
                def inner(fn):
                    setattr(fn, "_pytest_skip", reason)
                    return fn
                return inner
            elif name == "parametrize":
                argnames = args[0] if args else ""
                argvalues = args[1] if len(args) > 1 else []
                def inner(fn):
                    setattr(fn, "_pytest_parametrize", (argnames, argvalues))
                    return fn
                return inner
            def inner(fn):
                return fn
            return inner
        return mark_decorator


mark = MarkHelper()


class MonkeyPatch:
    """Standard pytest monkeypatch replacement."""

    def __init__(self):
        self._setattrs = []
        self._setenvs = []

    def setattr(self, target, name, value=None):
        if value is None and isinstance(target, str):
            parts = target.rsplit(".", 1)
            import importlib
            mod = importlib.import_module(parts[0])
            name = parts[1]
            target = mod
        old = getattr(target, name)
        setattr(target, name, value)
        self._setattrs.append((target, name, old))

    def setenv(self, name: str, value: Any):
        old = os.environ.get(name)
        os.environ[name] = str(value)
        self._setenvs.append((name, old))

    def delenv(self, name: str, raising: bool = True):
        old = os.environ.get(name)
        if name in os.environ:
            del os.environ[name]
        elif raising:
            raise KeyError(name)
        self._setenvs.append((name, old))

    def syspath_prepend(self, path: str):
        sys.path.insert(0, str(path))
        self._setattrs.append((sys, "path", list(sys.path)))

    def undo(self):
        for target, name, old in reversed(self._setattrs):
            try:
                setattr(target, name, old)
            except Exception:
                pass
        for name, old in reversed(self._setenvs):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old


class TmpPathFactory:
    def __init__(self, cleanups):
        self.cleanups = cleanups

    def mktemp(self, basename: str = "") -> pathlib.Path:
        p = pathlib.Path(tempfile.mkdtemp(prefix=basename or "qeuph-tmp-"))
        self.cleanups.append(lambda: shutil.rmtree(str(p), ignore_errors=True))
        return p


def _resolve_fixtures(fn, fixture_map, active_cleanups, memo=None, inst=None):
    if memo is None:
        memo = {}
    sig = inspect.signature(fn)
    kwargs = {}
    for param_name in sig.parameters:
        if param_name == "self":
            continue
        if param_name in kwargs:
            continue
        if param_name in memo:
            kwargs[param_name] = memo[param_name]
            continue

        if param_name == "tmp_path":
            td = tempfile.mkdtemp(prefix="pytest-tmp-")
            active_cleanups.append(lambda p=td: shutil.rmtree(p, ignore_errors=True))
            val = pathlib.Path(td)
            memo["tmp_path"] = val
            kwargs["tmp_path"] = val
        elif param_name == "tmp_path_factory":
            val = TmpPathFactory(active_cleanups)
            memo["tmp_path_factory"] = val
            kwargs["tmp_path_factory"] = val
        elif param_name == "monkeypatch":
            mp = MonkeyPatch()
            active_cleanups.append(mp.undo)
            memo["monkeypatch"] = mp
            kwargs["monkeypatch"] = mp
        elif param_name in fixture_map:
            fix_fn = fixture_map[param_name]
            fix_kwargs = _resolve_fixtures(fix_fn, fixture_map, active_cleanups, memo, inst=inst)
            call_kwargs = dict(fix_kwargs)
            call_args = []
            fix_sig = inspect.signature(fix_fn)
            if "self" in fix_sig.parameters and inst is not None:
                call_args.append(inst)

            if inspect.isgeneratorfunction(fix_fn):
                gen = fix_fn(*call_args, **call_kwargs)
                val = next(gen)
                def make_cleanup(g=gen):
                    try:
                        next(g)
                    except (StopIteration, Exception):
                        pass
                active_cleanups.append(make_cleanup)
            else:
                val = fix_fn(*call_args, **call_kwargs)
            memo[param_name] = val
            kwargs[param_name] = val

    return kwargs


def init_tests_package(tests_dir: str):
    abs_dir = os.path.abspath(tests_dir)
    if "tests" not in sys.modules:
        pkg = types.ModuleType("tests")
        pkg.__path__ = [abs_dir]
        pkg.__file__ = os.path.join(abs_dir, "__init__.py")
        sys.modules["tests"] = pkg

    conftest_path = os.path.join(abs_dir, "conftest.py")
    if os.path.isfile(conftest_path) and "tests.conftest" not in sys.modules:
        spec = importlib.util.spec_from_file_location("tests.conftest", conftest_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["tests.conftest"] = mod
            sys.modules["conftest"] = mod
            spec.loader.exec_module(mod)


def run_test_file(path: str) -> Tuple[int, int, int]:
    """Runs tests in a single file. Returns (passed, skipped, failed)."""
    tests_dir = os.path.dirname(os.path.abspath(path))
    init_tests_package(tests_dir)

    mod_base = os.path.splitext(os.path.basename(path))[0]
    full_mod_name = f"tests.{mod_base}"

    spec = importlib.util.spec_from_file_location(full_mod_name, path)
    if spec is None or spec.loader is None:
        return 0, 0, 1
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "tests"
    sys.modules[full_mod_name] = mod
    sys.modules[mod_base] = mod

    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"ERROR importing {path}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return 0, 0, 1

    local_fixtures = dict(_GLOBAL_FIXTURES)
    for attr_name in dir(mod):
        val = getattr(mod, attr_name)
        if callable(val) and (getattr(val, "_is_pytest_fixture", False) or attr_name in _GLOBAL_FIXTURES):
            local_fixtures[attr_name] = val

    passed, skipped, failed = 0, 0, 0
    test_callables = []

    for attr_name in dir(mod):
        val = getattr(mod, attr_name)
        if inspect.isclass(val) and attr_name.startswith("Test"):
            # Check for class-level fixtures
            cls_fixtures = dict(local_fixtures)
            for m_name in dir(val):
                m = getattr(val, m_name)
                if callable(m) and getattr(m, "_is_pytest_fixture", False):
                    cls_fixtures[m_name] = m
            for m_name in dir(val):
                if m_name.startswith("test_"):
                    test_callables.append((f"{attr_name}::{m_name}", getattr(val, m_name), val, cls_fixtures))
        elif callable(val) and attr_name.startswith("test_"):
            test_callables.append((attr_name, val, None, local_fixtures))

    for name, fn, cls, fixtures in test_callables:
        if cls is not None:
            cls_skipif = getattr(cls, "_pytest_skipif", None)
            if cls_skipif and cls_skipif[0]:
                skipped += 1
                continue
            cls_skip = getattr(cls, "_pytest_skip", None)
            if cls_skip:
                skipped += 1
                continue

        skipif = getattr(fn, "_pytest_skipif", None)
        if skipif and skipif[0]:
            skipped += 1
            continue
        skip_msg = getattr(fn, "_pytest_skip", None)
        if skip_msg:
            skipped += 1
            continue

        cleanups = []
        try:
            inst = cls() if cls is not None else None
            kwargs = _resolve_fixtures(fn, fixtures, cleanups, inst=inst)
            if inst is not None:
                fn(inst, **kwargs)
            else:
                fn(**kwargs)
            passed += 1
        except SkipException:
            skipped += 1
        except Exception as e:
            failed += 1
            print(f"FAILED {path}::{name}: {type(e).__name__}: {e}", flush=True)
        finally:
            for cu in reversed(cleanups):
                try:
                    cu()
                except Exception:
                    pass

    return passed, skipped, failed


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv[1:]

    test_dirs = [a for a in args if not a.startswith("-")] or ["tests/"]

    files_to_run = []
    for target in test_dirs:
        if os.path.isfile(target):
            files_to_run.append(target)
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for f in sorted(files):
                    if f.startswith("test_") and f.endswith(".py"):
                        files_to_run.append(os.path.join(root, f))

    total_passed, total_skipped, total_failed = 0, 0, 0
    t_start = time.time()
    print(f"running {len(files_to_run)} test files...", flush=True)

    for fpath in files_to_run:
        p, s, fa = run_test_file(fpath)
        total_passed += p
        total_skipped += s
        total_failed += fa
        status = "PASSED" if fa == 0 else "FAILED"
        print(f"  {fpath:35s} {status:6s} ({p} passed, {s} skipped, {fa} failed)", flush=True)

    duration = time.time() - t_start
    print("=" * 60, flush=True)
    print(f"Results: {total_passed} passed, {total_skipped} skipped, "
          f"{total_failed} failed in {duration:.2f}s", flush=True)

    return 1 if total_failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
