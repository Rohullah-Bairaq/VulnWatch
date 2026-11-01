"""Tkinter desktop interface for the local VulnWatch application."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from datetime import date
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from fastapi import HTTPException
from pydantic import ValidationError

from vulnwatch.database import initialize_database
from vulnwatch.integrations.nmap import NmapImportError, parse_nmap_xml, store_nmap_inventory
from vulnwatch.integrations.nvd import NvdError, fetch_cve
from vulnwatch.routes import assets, findings, intelligence
from vulnwatch.schemas import AssetCreate, AssetUpdate, FindingCreate, FindingUpdate

SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")
STATUSES = ("Open", "In Progress", "Resolved")
SEVERITY_COLORS = {
    "Critical": "#c94350",
    "High": "#d8793e",
    "Medium": "#bc921f",
    "Low": "#16856c",
    "Unknown": "#788594",
}


class VulnWatchDesktop:
    """Main window and event handlers for the desktop application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("VulnWatch | Vulnerability Management")
        self.root.geometry("1180x760")
        self.root.minsize(900, 620)
        self.root.configure(background="#f3f6fa")
        self.status_text = tk.StringVar(value="Local database ready")
        self.asset_search = tk.StringVar()
        self.finding_search = tk.StringVar()
        self.finding_severity = tk.StringVar(value="All severities")
        self.finding_status = tk.StringVar(value="All statuses")
        self.assets_cache: list[dict] = []
        self.findings_cache: list[dict] = []
        self.nvd_record: dict | None = None
        self.background_results: queue.Queue = queue.Queue()
        self.background_busy = False

        self._configure_style()
        self._build_layout()
        self.refresh_all()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#f3f6fa")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f3f6fa", foreground="#263647", font=("TkDefaultFont", 10))
        style.configure("Muted.TLabel", foreground="#738295", font=("TkDefaultFont", 9))
        style.configure("Title.TLabel", foreground="#152231", font=("TkDefaultFont", 20, "bold"))
        style.configure("Section.TLabel", foreground="#334456", font=("TkDefaultFont", 13, "bold"))
        style.configure("CardValue.TLabel", foreground="#172738", font=("TkDefaultFont", 22, "bold"))
        style.configure("TButton", padding=(11, 6), font=("TkDefaultFont", 9))
        style.configure("Accent.TButton", padding=(11, 6), font=("TkDefaultFont", 9, "bold"))
        style.configure("Treeview", rowheight=29, font=("TkDefaultFont", 9), background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("TkDefaultFont", 9, "bold"), padding=7)
        style.configure("TNotebook", background="#f3f6fa", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(15, 8), font=("TkDefaultFont", 9, "bold"))

    def _build_layout(self) -> None:
        header = ttk.Frame(self.root, padding=(20, 17, 20, 11))
        header.pack(fill="x")
        brand = ttk.Frame(header)
        brand.pack(side="left", fill="x", expand=True)
        ttk.Label(brand, text="VulnWatch", style="Title.TLabel").pack(anchor="w")
        ttk.Label(brand, text="LOCAL VULNERABILITY MANAGEMENT", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(header, text="●  SQLite workspace", foreground="#18866c").pack(side="right", padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.dashboard_tab = ttk.Frame(self.notebook, padding=14)
        self.findings_tab = ttk.Frame(self.notebook, padding=14)
        self.assets_tab = ttk.Frame(self.notebook, padding=14)
        self.intelligence_tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(self.dashboard_tab, text="Overview")
        self.notebook.add(self.findings_tab, text="Findings")
        self.notebook.add(self.assets_tab, text="Assets")
        self.notebook.add(self.intelligence_tab, text="CVE Intelligence")
        self._build_dashboard_tab()
        self._build_findings_tab()
        self._build_assets_tab()
        self._build_intelligence_tab()

        footer = ttk.Frame(self.root, padding=(20, 0, 20, 9))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status_text, style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="NVD data is intelligence; asset applicability requires analyst verification.", style="Muted.TLabel").pack(side="right")

    def _build_dashboard_tab(self) -> None:
        ttk.Label(self.dashboard_tab, text="Security overview", style="Section.TLabel").pack(anchor="w", pady=(0, 12))
        cards = ttk.Frame(self.dashboard_tab)
        cards.pack(fill="x", pady=(0, 15))
        self.summary_values: dict[str, ttk.Label] = {}
        card_specs = (("finding_count", "TRACKED FINDINGS"), ("open_count", "OPEN FINDINGS"),
                      ("critical_count", "CRITICAL OPEN"), ("asset_count", "MANAGED ASSETS"),
                      ("unverified_count", "UNVERIFIED FINDINGS"))
        for column, (key, title) in enumerate(card_specs):
            card = ttk.Frame(cards, style="Panel.TFrame", padding=(13, 11))
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 0))
            cards.columnconfigure(column, weight=1)
            ttk.Label(card, text=title, style="Muted.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="0", style="CardValue.TLabel")
            value.pack(anchor="w", pady=(6, 0))
            self.summary_values[key] = value

        content = ttk.Frame(self.dashboard_tab)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)
        severity_panel = ttk.Frame(content, style="Panel.TFrame", padding=15)
        severity_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ttk.Label(severity_panel, text="Active severity distribution", style="Section.TLabel").pack(anchor="w", pady=(0, 12))
        self.severity_rows: dict[str, tuple[ttk.Label, ttk.Progressbar, ttk.Label]] = {}
        for severity in SEVERITIES:
            row = ttk.Frame(severity_panel, style="Panel.TFrame")
            row.pack(fill="x", pady=5)
            ttk.Label(row, text=severity, width=10, background="#ffffff").pack(side="left")
            bar = ttk.Progressbar(row, maximum=100, mode="determinate")
            bar.pack(side="left", fill="x", expand=True, padx=8)
            count_label = ttk.Label(row, text="0", width=4, anchor="e", background="#ffffff")
            count_label.pack(side="right")
            self.severity_rows[severity] = (row, bar, count_label)
        ttk.Label(severity_panel, text="Resolved findings are excluded from this distribution.", style="Muted.TLabel").pack(anchor="w", pady=(12, 0))

        recent_panel = ttk.Frame(content, style="Panel.TFrame", padding=15)
        recent_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        title_row = ttk.Frame(recent_panel, style="Panel.TFrame")
        title_row.pack(fill="x", pady=(0, 9))
        ttk.Label(title_row, text="Recent findings", style="Section.TLabel").pack(side="left")
        ttk.Button(title_row, text="View all", command=lambda: self.notebook.select(self.findings_tab)).pack(side="right")
        self.recent_tree = self._make_tree(recent_panel, ("cve", "title", "severity", "status"), (130, 260, 90, 110))
        self.recent_tree.pack(fill="both", expand=True)
        self.recent_tree.bind("<Double-1>", lambda _event: self._view_selected_finding(self.recent_tree))

    def _build_findings_tab(self) -> None:
        toolbar = ttk.Frame(self.findings_tab)
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Label(toolbar, text="Vulnerability findings", style="Section.TLabel").pack(side="left", padx=(0, 12))
        self.finding_search_entry = ttk.Entry(toolbar, textvariable=self.finding_search, width=25)
        self.finding_search_entry.pack(side="left", padx=(0, 7))
        self.finding_search_entry.insert(0, "Search CVE, title, asset")
        self.finding_search_entry.bind("<FocusIn>", self._clear_search_placeholder)
        self.finding_search.trace_add("write", lambda *_args: self.refresh_findings())
        severity_box = ttk.Combobox(toolbar, textvariable=self.finding_severity, values=("All severities", *SEVERITIES), state="readonly", width=15)
        severity_box.pack(side="left", padx=5)
        severity_box.bind("<<ComboboxSelected>>", lambda _event: self.refresh_findings())
        status_box = ttk.Combobox(toolbar, textvariable=self.finding_status, values=("All statuses", *STATUSES), state="readonly", width=14)
        status_box.pack(side="left", padx=5)
        status_box.bind("<<ComboboxSelected>>", lambda _event: self.refresh_findings())

        actions = ttk.Frame(self.findings_tab)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="＋ New finding", style="Accent.TButton", command=self._new_finding).pack(side="left")
        ttk.Button(actions, text="View details", command=lambda: self._view_selected_finding(self.findings_tree)).pack(side="left", padx=6)
        ttk.Button(actions, text="Update status / notes", command=self._edit_finding).pack(side="left")
        ttk.Button(actions, text="Delete", command=self._delete_finding).pack(side="left", padx=6)
        ttk.Button(actions, text="Refresh", command=self.refresh_findings).pack(side="right")

        self.findings_tree = self._make_tree(
            self.findings_tab,
            ("cve", "title", "asset", "severity", "status", "verification", "discovered"),
            (145, 260, 180, 95, 110, 105, 100),
        )
        self.findings_tree.pack(fill="both", expand=True)
        self.findings_tree.bind("<Double-1>", lambda _event: self._view_selected_finding(self.findings_tree))

    def _build_assets_tab(self) -> None:
        toolbar = ttk.Frame(self.assets_tab)
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Label(toolbar, text="Asset inventory", style="Section.TLabel").pack(side="left", padx=(0, 12))
        ttk.Label(toolbar, text="Filter:").pack(side="left")
        search = ttk.Entry(toolbar, textvariable=self.asset_search, width=30)
        search.pack(side="left", padx=7)
        self.asset_search.trace_add("write", lambda *_args: self._populate_assets())
        ttk.Button(toolbar, text="＋ Add asset", style="Accent.TButton", command=self._new_asset).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Edit selected", command=self._edit_asset).pack(side="left", padx=5)
        ttk.Button(toolbar, text="View details", command=self._view_asset).pack(side="left", padx=5)
        ttk.Button(toolbar, text="Import Nmap XML", command=self._import_nmap).pack(side="right")

        self.assets_tree = self._make_tree(
            self.assets_tab,
            ("name", "ip", "hostname", "operating_system", "source", "findings"),
            (190, 140, 190, 220, 100, 90),
        )
        self.assets_tree.pack(fill="both", expand=True)
        self.assets_tree.bind("<Double-1>", lambda _event: self._view_asset())
        ttk.Label(self.assets_tab, text="Nmap-imported services are inventory only; they do not create vulnerability findings.", style="Muted.TLabel").pack(anchor="w", pady=(8, 0))

    def _build_intelligence_tab(self) -> None:
        top = ttk.Frame(self.intelligence_tab)
        top.pack(fill="x", pady=(0, 12))
        ttk.Label(top, text="NVD CVE intelligence", style="Section.TLabel").pack(side="left", padx=(0, 12))
        self.cve_input = ttk.Entry(top, width=24)
        self.cve_input.pack(side="left", padx=(0, 7))
        self.cve_input.insert(0, "CVE-2021-44228")
        ttk.Button(top, text="Search NVD", style="Accent.TButton", command=self._search_nvd).pack(side="left")
        self.save_cve_button = ttk.Button(top, text="Save intelligence record", command=self._save_nvd_record, state="disabled")
        self.save_cve_button.pack(side="left", padx=7)
        ttk.Label(self.intelligence_tab, text="NVD records describe CVEs. Saving intelligence does not create or verify an asset finding.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        preview_panel = ttk.Frame(self.intelligence_tab, style="Panel.TFrame", padding=12)
        preview_panel.pack(fill="x", pady=(0, 14))
        ttk.Label(preview_panel, text="Lookup result", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.nvd_preview = tk.Text(preview_panel, height=7, wrap="word", borderwidth=0, background="#ffffff", foreground="#354456", font=("TkDefaultFont", 10), state="disabled")
        self.nvd_preview.pack(fill="x")
        ttk.Label(self.intelligence_tab, text="Previously imported records", style="Section.TLabel").pack(anchor="w", pady=(3, 8))
        self.intelligence_tree = self._make_tree(self.intelligence_tab, ("cve", "title", "severity", "score", "imported"), (150, 540, 100, 90, 180))
        self.intelligence_tree.pack(fill="both", expand=True)

    @staticmethod
    def _make_tree(parent: ttk.Frame, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        labels = {
            "cve": "CVE ID", "title": "Title", "asset": "Affected asset", "severity": "Severity",
            "status": "Status", "verification": "Verification", "discovered": "Discovered",
            "name": "Name", "ip": "IP address", "hostname": "Hostname", "operating_system": "Operating system",
            "source": "Source", "findings": "Findings", "score": "CVSS", "imported": "Imported",
        }
        for column, width in zip(columns, widths):
            tree.heading(column, text=labels[column])
            tree.column(column, width=width, minwidth=70, anchor="w", stretch=True)
        tree.tag_configure("Critical", foreground=SEVERITY_COLORS["Critical"])
        tree.tag_configure("High", foreground=SEVERITY_COLORS["High"])
        tree.tag_configure("Medium", foreground=SEVERITY_COLORS["Medium"])
        tree.tag_configure("Low", foreground=SEVERITY_COLORS["Low"])
        return tree

    def _clear_search_placeholder(self, _event: tk.Event) -> None:
        if self.finding_search.get() == "Search CVE, title, asset":
            self.finding_search.set("")

    def refresh_all(self) -> None:
        try:
            self.refresh_dashboard()
            self.refresh_findings()
            self.refresh_assets()
            self.refresh_intelligence()
            self.status_text.set("Local SQLite data loaded")
        except Exception as error:  # Show an actionable startup error instead of crashing silently.
            messagebox.showerror("Could not load VulnWatch", self._error_text(error), parent=self.root)

    def refresh_dashboard(self) -> None:
        summary = findings.dashboard_summary()
        for key, label in self.summary_values.items():
            label.configure(text=str(summary.get(key, 0)))
        counts = summary["severity_counts"]
        maximum = max(counts.values(), default=0) or 1
        for severity, (_row, bar, count_label) in self.severity_rows.items():
            bar.configure(value=(counts.get(severity, 0) / maximum) * 100)
            count_label.configure(text=str(counts.get(severity, 0)))
        recent = findings.list_findings(search="", severity=None, status=None)[:8]
        self._fill_findings_tree(self.recent_tree, recent, include_asset=False)

    def refresh_findings(self) -> None:
        if not hasattr(self, "findings_tree"):
            return
        search = self.finding_search.get()
        if search == "Search CVE, title, asset":
            search = ""
        severity = self.finding_severity.get()
        status = self.finding_status.get()
        rows = findings.list_findings(search=search, severity=None if severity == "All severities" else severity,
                                      status=None if status == "All statuses" else status)
        self.findings_cache = rows
        self._fill_findings_tree(self.findings_tree, rows, include_asset=True)

    @staticmethod
    def _fill_findings_tree(tree: ttk.Treeview, rows: list[dict], include_asset: bool) -> None:
        tree.delete(*tree.get_children())
        for finding in rows:
            if include_asset:
                values = [finding["cve_id"], finding["title"],
                          f"{finding['asset_name']} ({finding['asset_ip']})", finding["severity"],
                          finding["status"], "Verified" if finding["verified"] else "Unverified",
                          finding["discovered_date"]]
            else:
                values = [finding["cve_id"], finding["title"], finding["severity"], finding["status"]]
            tree.insert("", "end", iid=str(finding["id"]), values=values, tags=(finding["severity"],))

    def refresh_assets(self) -> None:
        self.assets_cache = assets.list_assets()
        self._populate_assets()

    def _populate_assets(self) -> None:
        if not hasattr(self, "assets_tree"):
            return
        filter_text = self.asset_search.get().strip().casefold()
        self.assets_tree.delete(*self.assets_tree.get_children())
        for asset in self.assets_cache:
            searchable = " ".join(str(asset.get(key) or "") for key in ("name", "ip_address", "hostname", "operating_system", "source"))
            if filter_text and filter_text not in searchable.casefold():
                continue
            self.assets_tree.insert("", "end", iid=str(asset["id"]), values=(
                asset["name"], asset["ip_address"], asset["hostname"] or "—",
                asset["operating_system"] or "—", asset["source"], asset["finding_count"],
            ))

    def refresh_intelligence(self) -> None:
        if not hasattr(self, "intelligence_tree"):
            return
        records = intelligence.list_imported_cves()
        self.intelligence_tree.delete(*self.intelligence_tree.get_children())
        for record in records:
            self.intelligence_tree.insert("", "end", values=(record["cve_id"], record["title"],
                record["severity"], record["cvss_score"] if record["cvss_score"] is not None else "—",
                record["imported_at"]))

    @staticmethod
    def _error_text(error: Exception) -> str:
        if isinstance(error, HTTPException):
            return str(error.detail)
        if isinstance(error, ValidationError):
            details = error.errors()
            return details[0]["msg"] if details else "Please check the entered values."
        if isinstance(error, NvdError):
            return str(error)
        if isinstance(error, NmapImportError):
            return str(error)
        if isinstance(error, ValueError):
            return str(error)
        return str(error) or "An unexpected problem occurred."

    def _selected_id(self, tree: ttk.Treeview, item_name: str) -> int | None:
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Select a record", f"Select {item_name} first.", parent=self.root)
            return None
        return int(selection[0])

    def _new_asset(self) -> None:
        self._asset_form()

    def _edit_asset(self) -> None:
        asset_id = self._selected_id(self.assets_tree, "an asset")
        if asset_id is None:
            return
        try:
            self._asset_form(assets.get_asset(asset_id))
        except Exception as error:
            messagebox.showerror("Could not open asset", self._error_text(error), parent=self.root)

    def _asset_form(self, asset: dict | None = None) -> None:
        editing = asset is not None
        window = self._modal("Edit asset" if editing else "Add asset", "470x360")
        ttk.Label(window, text="Update the local asset record." if editing else "Add an endpoint to the local inventory.", style="Muted.TLabel").pack(anchor="w", pady=(0, 12))
        form = ttk.Frame(window)
        form.pack(fill="x", expand=True)
        fields = (("Asset name", "name"), ("IP address", "ip_address"), ("Hostname", "hostname"), ("Operating system", "operating_system"))
        entries: dict[str, ttk.Entry] = {}
        for row, (label, key) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=7)
            entry = ttk.Entry(form)
            entry.grid(row=row, column=1, sticky="ew", pady=7, padx=(12, 0))
            entry.insert(0, str(asset.get(key) or "") if editing else "")
            entries[key] = entry
        form.columnconfigure(1, weight=1)

        def save() -> None:
            try:
                values = {key: entry.get().strip() or None for key, entry in entries.items()}
                values["name"] = values["name"] or ""
                values["ip_address"] = values["ip_address"] or ""
                model = AssetUpdate(**values) if editing else AssetCreate(**values)
                result = assets.update_asset(asset["id"], model) if editing else assets.create_asset(model)
                window.winfo_toplevel().destroy()
                self.refresh_assets()
                self.refresh_dashboard()
                self.status_text.set(f"Saved asset: {result['name']}")
            except Exception as error:
                messagebox.showerror("Could not save asset", self._error_text(error), parent=window)

        button_row = ttk.Frame(window)
        button_row.pack(fill="x", pady=(14, 0))
        ttk.Button(button_row, text="Cancel", command=window.winfo_toplevel().destroy).pack(side="right", padx=(6, 0))
        ttk.Button(button_row, text="Save asset", style="Accent.TButton", command=save).pack(side="right")

    def _view_asset(self) -> None:
        asset_id = self._selected_id(self.assets_tree, "an asset")
        if asset_id is None:
            return
        try:
            asset = assets.get_asset(asset_id)
        except Exception as error:
            messagebox.showerror("Could not load asset", self._error_text(error), parent=self.root)
            return
        services = asset["services"]
        service_lines = [f"{service['protocol']}/{service['port']}  {service['service_name']}  {service['product']} {service['version']}".strip() for service in services]
        details = [
            f"Name: {asset['name']}", f"IP address: {asset['ip_address']}",
            f"Hostname: {asset['hostname'] or 'Not set'}", f"Operating system: {asset['operating_system'] or 'Not set'}",
            f"Inventory source: {asset['source']}", f"Linked findings: {asset['finding_count']}",
            "", "Open service inventory:", *(service_lines or ["No imported service records."]),
            "", "Services are inventory evidence only. They do not establish CVE applicability.",
        ]
        self._show_text_window(f"Asset: {asset['name']}", "\n".join(details))

    def _new_finding(self) -> None:
        try:
            available_assets = assets.list_assets()
        except Exception as error:
            messagebox.showerror("Could not load assets", self._error_text(error), parent=self.root)
            return
        if not available_assets:
            messagebox.showinfo("Add an asset first", "Create or import an asset before adding a finding.", parent=self.root)
            return

        window = self._modal("Create vulnerability finding", "620x650")
        ttk.Label(window, text="Create an analyst-managed finding. Asset verification is optional but explicit.", style="Muted.TLabel").pack(anchor="w", pady=(0, 10))
        form = ttk.Frame(window)
        form.pack(fill="both", expand=True)
        entries: dict[str, ttk.Entry] = {}
        row = 0

        def add_entry(label: str, key: str, default: str = "") -> None:
            nonlocal row
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(form)
            entry.grid(row=row, column=1, sticky="ew", pady=5, padx=(12, 0))
            if default:
                entry.insert(0, default)
            entries[key] = entry
            row += 1

        add_entry("CVE ID", "cve_id")
        add_entry("Title", "title")
        add_entry("CVSS score (optional)", "cvss_score")
        ttk.Label(form, text="Severity").grid(row=row, column=0, sticky="w", pady=5)
        severity = ttk.Combobox(form, values=SEVERITIES, state="readonly")
        severity.set("Unknown")
        severity.grid(row=row, column=1, sticky="ew", pady=5, padx=(12, 0))
        row += 1

        asset_labels = [f"{asset['name']} ({asset['ip_address']})" for asset in available_assets]
        asset_ids = {label: asset["id"] for label, asset in zip(asset_labels, available_assets)}
        ttk.Label(form, text="Affected asset").grid(row=row, column=0, sticky="w", pady=5)
        asset_choice = ttk.Combobox(form, values=asset_labels, state="readonly")
        asset_choice.current(0)
        asset_choice.grid(row=row, column=1, sticky="ew", pady=5, padx=(12, 0))
        row += 1
        add_entry("Discovered date (YYYY-MM-DD)", "discovered_date", date.today().isoformat())

        ttk.Label(form, text="Description").grid(row=row, column=0, sticky="nw", pady=5)
        description = tk.Text(form, height=4, wrap="word", font=("TkDefaultFont", 9))
        description.grid(row=row, column=1, sticky="ew", pady=5, padx=(12, 0))
        row += 1
        ttk.Label(form, text="Remediation notes").grid(row=row, column=0, sticky="nw", pady=5)
        notes = tk.Text(form, height=3, wrap="word", font=("TkDefaultFont", 9))
        notes.grid(row=row, column=1, sticky="ew", pady=5, padx=(12, 0))
        row += 1
        verified = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="I verified that this CVE applies to this asset", variable=verified).grid(row=row, column=1, sticky="w", pady=8)
        form.columnconfigure(1, weight=1)

        def save() -> None:
            try:
                score_text = entries["cvss_score"].get().strip()
                model = FindingCreate(
                    cve_id=entries["cve_id"].get().strip().upper(),
                    title=entries["title"].get().strip(),
                    cvss_score=float(score_text) if score_text else None,
                    severity=severity.get(), asset_id=asset_ids[asset_choice.get()],
                    discovered_date=entries["discovered_date"].get().strip(),
                    description=description.get("1.0", "end").strip(),
                    remediation_notes=notes.get("1.0", "end").strip(), verified=verified.get(),
                )
                findings.create_finding(model)
                window.winfo_toplevel().destroy()
                self.refresh_all()
                self.status_text.set(f"Created finding for {model.cve_id}")
            except Exception as error:
                messagebox.showerror("Could not create finding", self._error_text(error), parent=window)

        self._dialog_buttons(window, save, "Create finding")

    def _view_selected_finding(self, tree: ttk.Treeview) -> None:
        finding_id = self._selected_id(tree, "a finding")
        if finding_id is None:
            return
        try:
            finding = findings.get_finding(finding_id)
        except Exception as error:
            messagebox.showerror("Could not load finding", self._error_text(error), parent=self.root)
            return
        detail_text = (
            f"CVE: {finding['cve_id']}\nTitle: {finding['title']}\n\n"
            f"Asset: {finding['asset_name']} ({finding['asset_ip']})\nSeverity: {finding['severity']}\n"
            f"CVSS: {finding['cvss_score'] if finding['cvss_score'] is not None else 'Not supplied'}\n"
            f"Status: {finding['status']}\nDiscovered: {finding['discovered_date']}\n"
            f"Asset relationship: {'Verified by analyst' if finding['verified'] else 'UNVERIFIED'}\n\n"
            f"Description:\n{finding['description'] or 'No description supplied.'}\n\n"
            f"Remediation notes:\n{finding['remediation_notes'] or 'No notes yet.'}"
        )
        self._show_text_window(f"Finding {finding['cve_id']}", detail_text)

    def _edit_finding(self) -> None:
        finding_id = self._selected_id(self.findings_tree, "a finding")
        if finding_id is None:
            return
        try:
            finding = findings.get_finding(finding_id)
        except Exception as error:
            messagebox.showerror("Could not load finding", self._error_text(error), parent=self.root)
            return
        window = self._modal("Update finding", "520x380")
        ttk.Label(window, text=f"{finding['cve_id']}  ·  {finding['title']}", style="Section.TLabel").pack(anchor="w", pady=(0, 14))
        form = ttk.Frame(window)
        form.pack(fill="both", expand=True)
        ttk.Label(form, text="Remediation status").grid(row=0, column=0, sticky="w", pady=7)
        status = ttk.Combobox(form, values=STATUSES, state="readonly")
        status.set(finding["status"])
        status.grid(row=0, column=1, sticky="ew", pady=7, padx=(12, 0))
        ttk.Label(form, text="Remediation notes").grid(row=1, column=0, sticky="nw", pady=7)
        notes = tk.Text(form, height=7, wrap="word", font=("TkDefaultFont", 9))
        notes.insert("1.0", finding["remediation_notes"])
        notes.grid(row=1, column=1, sticky="ew", pady=7, padx=(12, 0))
        verified = tk.BooleanVar(value=bool(finding["verified"]))
        ttk.Checkbutton(form, text="Analyst has verified this asset relationship", variable=verified).grid(row=2, column=1, sticky="w", pady=8)
        form.columnconfigure(1, weight=1)

        def save() -> None:
            try:
                findings.update_finding(finding_id, FindingUpdate(
                    status=status.get(), remediation_notes=notes.get("1.0", "end").strip(), verified=verified.get(),
                ))
                window.winfo_toplevel().destroy()
                self.refresh_all()
                self.status_text.set(f"Updated {finding['cve_id']}")
            except Exception as error:
                messagebox.showerror("Could not update finding", self._error_text(error), parent=window)

        self._dialog_buttons(window, save, "Save changes")

    def _delete_finding(self) -> None:
        finding_id = self._selected_id(self.findings_tree, "a finding")
        if finding_id is None:
            return
        if not messagebox.askyesno("Delete finding", "Delete this finding? This cannot be undone.", parent=self.root):
            return
        try:
            findings.delete_finding(finding_id)
            self.refresh_all()
            self.status_text.set("Finding deleted")
        except Exception as error:
            messagebox.showerror("Could not delete finding", self._error_text(error), parent=self.root)

    def _import_nmap(self) -> None:
        filename = filedialog.askopenfilename(
            parent=self.root, title="Choose an existing Nmap XML file",
            filetypes=(("Nmap XML", "*.xml"), ("All files", "*.*")),
        )
        if not filename:
            return
        try:
            with open(filename, "rb") as scan_file:
                content = scan_file.read(5_000_001)
            hosts = parse_nmap_xml(content)
            asset_count, service_count = store_nmap_inventory(hosts)
            self.refresh_all()
            messagebox.showinfo(
                "Nmap inventory imported",
                f"Imported or updated {asset_count} assets and {service_count} open services.\n\n"
                "No vulnerability findings were inferred from service names or versions.",
                parent=self.root,
            )
        except (OSError, NmapImportError) as error:
            messagebox.showerror("Could not import Nmap XML", self._error_text(error), parent=self.root)
        except Exception as error:
            messagebox.showerror("Could not save Nmap inventory", self._error_text(error), parent=self.root)

    def _search_nvd(self) -> None:
        cve_id = self.cve_input.get().strip().upper()
        if not cve_id:
            messagebox.showinfo("Enter a CVE ID", "Enter a CVE ID such as CVE-2021-44228.", parent=self.root)
            return
        self.save_cve_button.configure(state="disabled")
        self._set_nvd_preview("Searching NVD. This may take a few seconds.")
        self._run_background("Searching NVD…", lambda: fetch_cve(cve_id), self._show_nvd_record)

    def _show_nvd_record(self, record: dict) -> None:
        self.nvd_record = record
        score = record["cvss_score"] if record["cvss_score"] is not None else "Not supplied"
        self._set_nvd_preview(
            f"{record['cve_id']}  |  {record['severity']}  |  CVSS {score}\n"
            f"Published: {record['published_at'] or 'Not supplied'}\n"
            f"NVD: {record['nvd_url']}\n\n{record['description'] or 'No English description supplied.'}\n\n"
            "This is imported vulnerability intelligence. It does not confirm that an inventoried asset is affected."
        )
        self.save_cve_button.configure(state="normal")
        self.status_text.set(f"NVD result loaded for {record['cve_id']}")

    def _save_nvd_record(self) -> None:
        if self.nvd_record is None:
            return
        try:
            intelligence.save_intelligence(self.nvd_record)
            self.refresh_intelligence()
            self.status_text.set(f"Saved NVD intelligence for {self.nvd_record['cve_id']}")
            messagebox.showinfo("Intelligence saved", "The CVE record was saved. No asset finding was created.", parent=self.root)
        except Exception as error:
            messagebox.showerror("Could not save intelligence", self._error_text(error), parent=self.root)

    def _set_nvd_preview(self, message: str) -> None:
        self.nvd_preview.configure(state="normal")
        self.nvd_preview.delete("1.0", "end")
        self.nvd_preview.insert("1.0", message)
        self.nvd_preview.configure(state="disabled")

    def _run_background(self, activity: str, task: Callable[[], object], on_success: Callable[[object], None]) -> None:
        if self.background_busy:
            messagebox.showinfo("Please wait", "The current background request is still running.", parent=self.root)
            return
        self.background_busy = True
        self.status_text.set(activity)

        def worker() -> None:
            try:
                self.background_results.put((task(), None))
            except Exception as error:
                self.background_results.put((None, error))

        threading.Thread(target=worker, name="vulnwatch-background-task", daemon=True).start()
        self.root.after(100, lambda: self._poll_background(on_success))

    def _poll_background(self, on_success: Callable[[object], None]) -> None:
        try:
            result, error = self.background_results.get_nowait()
        except queue.Empty:
            self.root.after(100, lambda: self._poll_background(on_success))
            return
        self.background_busy = False
        if error is not None:
            self._set_nvd_preview(self._error_text(error))
            self.status_text.set("NVD request failed")
            messagebox.showerror("NVD lookup failed", self._error_text(error), parent=self.root)
            return
        on_success(result)

    def _modal(self, title: str, geometry: str) -> ttk.Frame:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry(geometry)
        window.transient(self.root)
        window.grab_set()
        body = ttk.Frame(window, padding=17)
        body.pack(fill="both", expand=True)
        return body

    def _dialog_buttons(self, body: ttk.Frame, save: Callable[[], None], save_label: str) -> None:
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))
        window = body.winfo_toplevel()
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text=save_label, style="Accent.TButton", command=save).pack(side="right")

    def _show_text_window(self, title: str, contents: str) -> None:
        window = self._modal(title, "650x500")
        text = tk.Text(window, wrap="word", font=("TkDefaultFont", 10), padx=10, pady=10)
        text.pack(fill="both", expand=True)
        text.insert("1.0", contents)
        text.configure(state="disabled")
        ttk.Button(window, text="Close", command=window.winfo_toplevel().destroy).pack(anchor="e", pady=(10, 0))


def launch_desktop() -> None:
    """Initialize the existing local database and start Tk's event loop."""
    initialize_database()
    root = tk.Tk()
    VulnWatchDesktop(root)
    root.mainloop()
