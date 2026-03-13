# Lessons Learned

## 2026-03-13 - Bugfix: React Hooks Dependencies and Python Module Imports

- **Bug**: React Hook useEffect/useCallback missing dependencies causing ESLint warnings
- **Fix**: Wrapped functions with useCallback and added proper dependency arrays
- **Rule**: Always include function dependencies in useCallback/useEffect dependency arrays; use useCallback for functions passed to dependency arrays

- **Bug**: Python test imports failing with "No module named 'models.suppression_rules'"  
- **Fix**: Created missing `__init__.py` file in `api/models/` directory to make it a proper Python package
- **Rule**: All Python directories containing modules must have `__init__.py` files to be importable as packages

- **Bug**: Verification report showed failing imports despite file existence
- **Fix**: Module structure issue - directory without `__init__.py` cannot be imported as package
- **Rule**: When adding new model subdirectories, always create `__init__.py` files for proper package structure

## Patterns Added

- React hooks must include all dependencies or be wrapped with useCallback to prevent infinite re-renders
- Python package directories require `__init__.py` even if they only contain a single module
- Test imports should match the actual package structure after path manipulation with sys.path.insert()