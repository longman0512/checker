# main_runtime

Minimal runnable source bundle for the Login Credential Checker.

## Run

```bash
python run.py
```

or:

```bash
python src/main.py
```

## Install dependencies

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

## Included modules

- `src/main.py`
- `src/gui/app.py`
- `src/gui/styles.py`
- `src/checker.py`
- `src/parser.py`
- `src/proxy_manager.py`
- `src/page_analyzer.py`
- `src/form_cache.py`
- `src/advanced_checker.py`
- `src/credential_filter.py`
