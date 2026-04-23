# Login Credential Checker

Playwright-based desktop application for validating login credentials in bulk.

The app is optimized for very large files and focuses on checker workflows:

- stream-based file indexing (no full file load into RAM)
- fast paging and filtering
- parallel checking with configurable workers
- proxy rotation support
- Anti-Captcha API support
- screenshot capture and export

## Requirements

- Python 3.10+ (3.11 recommended)
- Playwright Chromium
- Dependencies from `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Optional virtualenv on Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
```

## Run

Windows helper:

```bash
start.bat
```

Or directly:

```bash
python run.py
```

Alternative entry:

```bash
python src/main.py
```

## Input Format

Supported credential line formats:

- `url:username:password`
- `url|username|password`
- `url;username;password`

Examples:

```txt
https://example.com/login:user@example.com:secret
example.com/login|admin|pass123
portal.example.net;john;P@ssw0rd
```

Notes:

- Lines beginning with `#` are ignored.
- Invalid lines are skipped.
- If URL has no scheme, `https://` is added automatically.

## Checker Workflow

1. Click **Open File** and choose a credential file.
2. Configure settings in the top controls:
   - `Login URL` (optional override)
   - `Success URL` + `Exact` mode
   - `Success DOM` hint
   - Browser executable (optional)
   - `Workers` for parallel checks
   - `Anti-Captcha Key`
   - `Minimized` mode
   - Screenshot trigger mode
3. Use filters if needed:
   - Domain
   - URL contains
   - Status
   - Username mode (All / ID Only / Email Only)
4. Click **Check All**.
5. Use **Pause** / **Stop** when needed.
6. Review statuses in the table and open captured screenshots from the `📷` column.

## Toolbar Actions

- `Open File`: load credentials
- `Check All`: start checking
- `Stop`: stop running checks
- `Pause`: pause/resume checks
- `Export Results`: export filtered rows to CSV and dump file
- `Save as Dump`: export filtered rows as `url:username:password`
- `Clear Session`: remove saved session state (`state.json`)

## Advanced Controls

- `🌐 Proxy`: proxy list + rotation configuration
- `🎯 DOM Settings`: global selector/snippet overrides

## Result Statuses

Common statuses include:

- `SUCCESS`
- `FAILED`
- `UNKNOWN`
- `CAPTCHA`
- `UNREACHABLE`
- `TIMEOUT`
- `ERROR`
- `Stopped`

## Export Behavior

### Export Results

Creates:

- chosen CSV file with columns: `Domain,URL,Username,Password,Status,Note`
- matching dump file: `<export_name>_dump.txt`

### Save as Dump

Creates plain text output where each line is:

```txt
url:username:password
```

Both export options respect active filters.

## Runtime Files

The app may create/update:

- `state.json` - saved session state
- `form_cache.json` - cached form/result patterns
- `dom_settings.json` - global DOM selector settings
- `anti_captcha_settings.json` - Anti-Captcha API key
- `login_recipe.json` - recorded login recipe

## Troubleshooting

- **Playwright error / browser missing**
  - Run: `python -m playwright install chromium`
- **No rows loaded**
  - Verify credential lines follow supported format.
- **Many UNREACHABLE results**
  - Check proxy list/rotation, test with proxy disabled.
- **No screenshots captured**
  - Ensure screenshot mode is not `disabled`.

## Code Entry Points

- `run.py`
- `src/main.py`
- `src/gui/app.py`
- `src/checker.py`
- `src/parser.py`
- `src/proxy_manager.py`
