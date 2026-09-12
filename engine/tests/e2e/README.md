# e2e harnesses

Loop-driver integration harnesses absorbed from the former `audit-loop/`
(2026-09-13; the deterministic EVALUATE beat itself lives in
`motoko/loop_evaluate.py`, unit-tested by `tests/test_loop_evaluate.py`).

These are NOT auto-collected by pytest (`e2e_*.py` ≠ `test_*.py`): they
drive real LLM legs and real engagement graphs, so they run on demand:

```bash
cd engine
python3 tests/e2e/e2e_driver.py --help   # per-harness flags differ; check first
```

Each harness synthesizes a throwaway engagement under a temp root; none of
them should touch `engagements/` — if one does, it is a bug.
