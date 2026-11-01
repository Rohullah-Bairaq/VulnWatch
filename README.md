# VulnWatch

VulnWatch is a local-first vulnerability management portfolio application. Its primary interface is a PySide6 desktop window that embeds the existing FastAPI dashboard with Qt WebEngine. A Tkinter desktop interface remains available as a fallback. SQLite stores assets, vulnerability findings, imported NVD intelligence, and Nmap service inventory.

NVD records are vulnerability intelligence, not evidence that a particular asset is affected. Findings retain an explicit analyst verification flag. Nmap imports inventory hosts and open services only; they never launch a scan or automatically create a vulnerability finding.

## Requirements and setup

- Python 3.11 or newer.
- The existing project virtual environment at `.venv`.
- PySide6 with Qt WebEngine available in that Python installation. The project dependency installs PySide6; a graphical Linux session is needed to display the desktop window.
- Tkinter available if you want to use the fallback launcher. Some Linux Python builds package its Tcl/Tk support separately.
- FastAPI and Uvicorn run the local dashboard server inside the Qt launcher.

If project dependencies are not installed in `.venv`, install them there from the project directory:

```bash
source .venv/bin/activate
python -m pip install -e .
```

## Launch the Qt desktop application

From the project directory:

```bash
source .venv/bin/activate
python qt_desktop_app.py
```

VulnWatch opens in a standalone desktop window. The launcher starts the existing FastAPI app on an available loopback port, waits for its health endpoint, and embeds the dashboard. Closing the window shuts down the local server.

To use the Tkinter interface instead:

```bash
python desktop_app.py
```

By default, the app uses `data/vulnwatch.db`. Existing database records are kept. To use another database file, set `VULNWATCH_DB_PATH` before launching.

## Desktop features

- **Overview:** tracked/open/critical/unverified finding totals, asset count, and active severity distribution.
- **Findings:** view details, search and filter by severity/status, create findings, update remediation status/notes and analyst verification, and delete with confirmation.
- **Assets:** view, filter, add, and edit assets. Asset details include imported service inventory.
- **CVE intelligence:** search the official NVD CVE API, review the returned record, and save it locally without creating an asset finding. Internet access is needed for live lookups; an API key is optional and, if configured, is read from the `NVD_API_KEY` environment variable of the VulnWatch process.
- **Nmap XML:** import an existing XML output file to add/update asset and open-service inventory. Files are limited to 5 MB. No network scan is launched.

Nmap version strings are not vulnerability proof. The analyst decides whether a CVE applies and records that decision with the finding's verification control.

## Existing browser/API interface

The FastAPI application and browser dashboard are retained and are embedded by the Qt desktop launcher. To start the web interface separately:

```bash
source .venv/bin/activate
uvicorn vulnwatch.main:app --app-dir src --reload
```

The dashboard is then available at <http://127.0.0.1:8000>. This manual command uses Uvicorn's default port; the Qt desktop launch selects an available port automatically. The desktop and web interface use the same SQLite database and integration logic.

## Tests

Run the automated tests from the project directory:

```bash
source .venv/bin/activate
PYTHONPATH=src python -m unittest discover -s tests -v
```

Tests use temporary SQLite databases and mocked NVD responses. They do not change the application's saved database or depend on network access. GUI startup can also be smoke-tested in a graphical session by running `python desktop_app.py`.

## Project layout

```text
desktop_app.py             Desktop launcher
qt_desktop_app.py          PySide6 + Qt WebEngine launcher
src/vulnwatch/qt_desktop.py Qt window and local server lifecycle
src/vulnwatch/desktop.py   Tkinter fallback interface
src/vulnwatch/database.py SQLite setup and connections
src/vulnwatch/routes/     Shared asset, finding, and intelligence operations
src/vulnwatch/integrations/ NVD client and Nmap XML parsing/import
src/vulnwatch/static/     Browser dashboard assets and dark SOC theme
templates/                Retained browser dashboard HTML
tests/                    Automated tests and synthetic XML fixture
data/                     Persistent local SQLite database
```
