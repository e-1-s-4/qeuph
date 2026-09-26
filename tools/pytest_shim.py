"""Minimal standalone pytest shim for environments without pip/pytest installed.
Provides fixture, raises, fail, mark.skipif, and test discovery.
"""
from __future__ import annotations

import inspect
import os
import re
import sys
import time
import unittest


class _RaisesContext:
    def __init__(self, expected_exception, match: str | None = None):
        self.expected_exception = expected_exception
        self.match = match
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"Expected exception {self.expected_exception.__name__} was not raised")
        if not issubclass(exc_type, self.expected_exception):
            return False  # Let unexpected exception propagate
        if self.match:
            msg = str(exc_val)
            if not re.search(self.match, msg):
                raise AssertionError(f"Pattern {self.match!r} does not match {msg!r}")
        self.value = exc_val
        return True


def raises(expected_exception, match: str | None = None):
    return _RaisesContext(expected_exception, match)


def fail(msg: str = ""):
    raise AssertionError(msg)


def skip(reason: str = ""):
    raise unittest.SkipTest(reason)


class _Mark:
    def skip(self, reason: str = ""):
        def deco(fn):
            fn.__unittest_skip__ = True
            fn.__unittest_skip_why__ = reason
            return fn
        return deco

    def skipif(self, condition: bool, reason: str = ""):
        def deco(fn):
            if condition:
                fn.__unittest_skip__ = True
                fn.__unittest_skip_why__ = reason
            return fn
        return deco


mark = _Mark()


_FIXTURES: dict[str, callable] = {}


def fixture(scope: str = "function", **kwargs):
    def decorator(fn):
        fn._pytest_fixture = True
        fn._fixture_scope = scope
        _FIXTURES[fn.__name__] = fn
        return fn
    return decorator


def approx(expected, rel=1e-6, abs=1e-12):
    class Approx:
        def __eq__(self, actual):
            return abs(actual - expected) <= max(rel * max(abs(actual), abs(expected)), abs)
    return Approx()


# ---------------------------------------------------------------------------
# Test Runner Implementation
# ---------------------------------------------------------------------------
def _run_test_file(filepath: str) -> tuple[int, int, int]:
    """Runs tests in a test file and returns (passed, failed, skipped)."""
    import importlib.util

    mod_name = os.path.basename(filepath).replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, filepath)
    if spec is None or spec.loader is None:
        return 0, 1, 0
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod

    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"ERROR loading {filepath}: {e}")
        import traceback
        traceback.print_exc()
        return 0, 1, 0

    # Collect module-level fixtures
    mod_fixtures: dict[str, Any] = {}
    for name, obj in inspect.getmembers(mod):
        if getattr(obj, "_pytest_fixture", False):
            mod_fixtures[name] = obj

    fixture_cache: dict[str, Any] = {}

    def resolve_fixture(name: str):
        if name in fixture_cache:
            return fixture_cache[name]
        fn = mod_fixtures.get(name) or _FIXTURES.get(name)
        if fn is None:
            raise ValueError(f"Unknown fixture {name}")
        # Resolve dependencies of the fixture
        sig = inspect.signature(fn)
        args = {param: resolve_fixture(param) for param in sig.parameters}
        val = fn(**args)
        if inspect.isgenerator(val):
            gen = val
            val = next(gen)
            # Store teardown
            fixture_cache[f"__teardown_{name}"] = gen
        if getattr(fn, "_fixture_scope", "function") != "function":
            fixture_cache[name] = val
        return val

    passed = 0
    failed = 0
    skipped = 0

    # Find test classes and test functions
    test_items = []
    for name, obj in inspect.getmembers(mod):
        if inspect.isclass(obj) and (name.startswith("Test") or name.endswith("Test")):
            cls_skip = getattr(obj, "__unittest_skip__", False)
            cls_why = getattr(obj, "__unittest_skip_why__", "")
            inst = obj()
            for mname, mobj in inspect.getmembers(inst):
                if mname.startswith("test_") and callable(mobj):
                    test_items.append((f"{name}::{mname}", mobj, cls_skip, cls_why))
        elif inspect.isfunction(obj) and name.startswith("test_"):
            test_items.append((name, obj, False, ""))

    for item in test_items:
        test_name, fn, cls_skip, cls_why = item
        is_skip = getattr(fn, "__unittest_skip__", False) or cls_skip
        why_skip = getattr(fn, "__unittest_skip_why__", "") or cls_why
        if is_skip:
            print(f"  SKIP {test_name}: {why_skip}")
            skipped += 1
            continue

        test_cache = dict(fixture_cache)  # Copy module-level cache

        def resolve_fixture(name: str):
            if name in test_cache:
                return test_cache[name]
            fn_fix = mod_fixtures.get(name) or _FIXTURES.get(name)
            if fn_fix is None:
                raise ValueError(f"Unknown fixture {name}")
            sig = inspect.signature(fn_fix)
            args = {param: resolve_fixture(param) for param in sig.parameters}
            val = fn_fix(**args)
            if inspect.isgenerator(val):
                gen = val
                val = next(gen)
                fixture_cache[f"__teardown_{name}"] = gen
            test_cache[name] = val
            if getattr(fn_fix, "_fixture_scope", "function") != "function":
                fixture_cache[name] = val
            return val

        try:
            sig = inspect.signature(fn)
            kwargs = {}
            for param in sig.parameters:
                kwargs[param] = resolve_fixture(param)
            fn(**kwargs)
            passed += 1
            print(f"  PASS {test_name}")
        except unittest.SkipTest as e:
            print(f"  SKIP {test_name}: {e}")
            skipped += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL {test_name}: {e}")
            import traceback
            traceback.print_exc()

    # Teardown module generators
    for k, gen in list(fixture_cache.items()):
        if k.startswith("__teardown_"):
            try:
                next(gen)
            except StopIteration:
                pass
            except Exception as e:
                print(f"Teardown error for {k}: {e}")

    return passed, failed, skipped


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    test_dirs_or_files = []
    for a in args:
        if not a.startswith("-"):
            test_dirs_or_files.append(a)

    if not test_dirs_or_files:
        test_dirs_or_files = ["tests"]

    all_files = []
    for target in test_dirs_or_files:
        if os.path.isfile(target):
            all_files.append(target)
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for f in sorted(files):
                    if f.startswith("test_") and f.endswith(".py"):
                        all_files.append(os.path.join(root, f))

    all_files.sort()
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    t0 = time.time()
    for f in all_files:
        print(f"\n=== Running {f} ===")
        p, fail_count, s = _run_test_file(f)
        total_passed += p
        total_failed += fail_count
        total_skipped += s

    dt = time.time() - t0
    print(f"\n========================================================")
    print(f"Results: {total_passed} passed, {total_failed} failed, {total_skipped} skipped in {dt:.2f}s")
    print(f"========================================================")
    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
