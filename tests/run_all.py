"""Run every Aegis test module. `python tests/run_all.py`

Stdlib only, on purpose: the test suite should never be the reason someone can't run
this repo. Each module is also runnable on its own.
"""
import importlib
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

MODULES = ["test_detection", "test_reasoner", "test_live_paths", "test_regressions",
           "test_eval"]


def main():
    passed = failed = 0
    failures = []

    for name in MODULES:
        module = importlib.import_module(name)
        print(f"\n{name}")
        for attr in sorted(dir(module)):
            if not attr.startswith("test_"):
                continue
            fn = getattr(module, attr)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"  PASS {attr}")
            except AssertionError as e:
                failed += 1
                failures.append(f"{name}.{attr}: {e}")
                print(f"  FAIL {attr}: {e}")
            except Exception:                                  # noqa: BLE001
                failed += 1
                failures.append(f"{name}.{attr}\n{traceback.format_exc()}")
                print(f"  ERROR {attr}")
                traceback.print_exc()
        if hasattr(module, "report"):
            module.report()

    print(f"\n{'=' * 60}\n{passed} passed, {failed} failed")
    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
