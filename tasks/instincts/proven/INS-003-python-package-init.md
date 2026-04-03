---
id: INS-003
title: Python directories need __init__.py for imports
status: proven
confidence: 0.8
created: 2026-03-13
proven_at: 2026-03-13
source: lesson
tags: [python, imports, packaging]
---

All Python directories containing modules must have `__init__.py` files. When adding new model subdirectories, always create `__init__.py` for proper package structure. Test imports should match actual package structure after sys.path manipulation.

**Evidence:** "No module named 'models.suppression_rules'" fixed by adding missing __init__.py.
