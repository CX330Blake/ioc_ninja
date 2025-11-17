from binaryninja.binaryview import BinaryView
from binaryninja.log import log_info
import time
import csv
import re

from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QCheckBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QScrollArea,
    QGroupBox,
    QLineEdit,
    QLabel,
    QSplitter,
    QFileDialog,
    QMenu,
    QProgressBar,
    QAbstractItemView,
    QSizePolicy,
    QTreeWidget,
    QTreeWidgetItem,
    QStyle,
)
from PySide6.QtCore import Qt, QObject, QThread, Signal

from . import ioc_logic
from .tld_data import VALID_TLDS

import subprocess
import platform
import socket
import shutil
import hashlib


class IoCScanWorker(QObject):
    """Background worker to scan strings with progress and cancel."""

    progress = Signal(int, int)  # processed, total
    partial = Signal(list)  # list of (Type, Value, AddressCombined)
    finished = Signal(list, int, float)  # results, scanned_count, elapsed
    failed = Signal(str)
    canceled = Signal()

    def __init__(self, bv: BinaryView, patterns):
        super().__init__()
        self.bv = bv
        self.patterns = patterns
        self._cancel = False
        self._domain_cache = {}
        self._changed_keys = set()

    def cancel(self):
        self._cancel = True

    def run(self):
        start = time.time()
        try:
            strings = ioc_logic.collect_strings_from_bv(self.bv)
            total = len(strings)
            # Aggregate findings by (Type, Value) -> set(addresses)
            agg = {}
            # If user checked hash types, query Binary Ninja's file-hash API first.
            if self.patterns and any(t in self.patterns for t in ("MD5", "SHA1", "SHA256")):
                try:
                    f = getattr(self.bv, 'file', None)
                    if f is not None:
                        if "MD5" in self.patterns:
                            md5 = getattr(f, 'md5', None)
                            if md5:
                                agg.setdefault(("MD5", md5), set()).add("N/A")
                        if "SHA1" in self.patterns:
                            sha1 = getattr(f, 'sha1', None)
                            if sha1:
                                agg.setdefault(("SHA1", sha1), set()).add("N/A")
                        if "SHA256" in self.patterns:
                            sha256 = getattr(f, 'sha256', None)
                            if sha256:
                                agg.setdefault(("SHA256", sha256), set()).add("N/A")
                except Exception:
                    pass
                # If API did not yield hashes, fall back to hashing bytes once
                if ("MD5",) or ("SHA1",) or ("SHA256",):
                    need_md5 = ("MD5" in self.patterns) and not any(k[0]=="MD5" for k in agg.keys())
                    need_sha1 = ("SHA1" in self.patterns) and not any(k[0]=="SHA1" for k in agg.keys())
                    need_sha256 = ("SHA256" in self.patterns) and not any(k[0]=="SHA256" for k in agg.keys())
                    if need_md5 or need_sha1 or need_sha256:
                        try:
                            data = b""
                            length = getattr(self.bv, "end", None)
                            if length:
                                data = self.bv.read(0, int(length)) or b""
                            if not data and hasattr(self.bv, 'parent_view') and hasattr(self.bv.parent_view, 'end'):
                                data = self.bv.parent_view.read(0, int(self.bv.parent_view.end)) or b""
                            if data:
                                if need_md5:
                                    agg.setdefault(("MD5", hashlib.md5(data).hexdigest()), set()).add("N/A")
                                if need_sha1:
                                    agg.setdefault(("SHA1", hashlib.sha1(data).hexdigest()), set()).add("N/A")
                                if need_sha256:
                                    agg.setdefault(("SHA256", hashlib.sha256(data).hexdigest()), set()).add("N/A")
                        except Exception:
                            pass
            processed = 0
            for addr, s in strings:
                if self._cancel:
                    self.canceled.emit()
                    return
                try:
                    allowed = set(self.patterns.keys()) if self.patterns else None
                    matches = ioc_logic.match_iocs_in_string(s, self.patterns, allowed)
                    for k, vals in matches.items():
                        for v in vals:
                            # Validate domain TLD before any network checks
                            if k == "Domain" and not self._tld_is_valid(v):
                                continue
                            # Filter domain by ping reachability before output
                            if k == "Domain" and not self._domain_is_alive(v):
                                continue
                            addr_str = hex(addr) if isinstance(addr, int) else "N/A"
                            key = (k, v)
                            bucket = agg.get(key)
                            if bucket is None:
                                bucket = set()
                                agg[key] = bucket
                            before = len(bucket)
                            bucket.add(addr_str)
                            if len(bucket) != before:
                                self._changed_keys.add(key)
                except Exception:
                    # keep scanning despite individual failures
                    pass
                processed += 1
                if processed % 100 == 0 or processed == total:
                    if self._changed_keys:
                        partial_rows = []
                        for ioc_type, value in sorted(
                            self._changed_keys, key=lambda x: (x[0], x[1])
                        ):
                            addrs = agg.get((ioc_type, value), set())
                            numeric_addrs = sorted(
                                [a for a in addrs if a != "N/A"],
                                key=lambda x: int(x, 16),
                            )
                            if "N/A" in addrs:
                                numeric_addrs.append("N/A")
                            addr_join = ", ".join(numeric_addrs)
                            partial_rows.append((ioc_type, value, addr_join))
                        self.partial.emit(partial_rows)
                        self._changed_keys.clear()
                    self.progress.emit(processed, total)
            # Flatten aggregated map into list of rows with combined addresses
            results = []
            for (ioc_type, value), addrs in agg.items():
                # Keep deterministic order: numeric addresses first sorted, then N/A
                numeric_addrs = sorted(
                    [a for a in addrs if a != "N/A"], key=lambda x: int(x, 16)
                )
                if "N/A" in addrs:
                    numeric_addrs.append("N/A")
                addr_join = ", ".join(numeric_addrs)
                results.append((ioc_type, value, addr_join))
            # Stable sort by Type then Value for nicer UX
            results.sort(key=lambda r: (r[0], r[1]))
            elapsed = time.time() - start
            self.finished.emit(results, processed, elapsed)
        except Exception as e:
            self.failed.emit(str(e))

    def _domain_is_alive(self, domain: str) -> bool:
        """Best-effort ping check with caching and sane timeouts.
        - Try system ping with count=1 and process timeout.
        - Fallback to TCP connect on port 80 with short timeout.
        - Cache results to avoid repeated checks.
        """
        # Normalize domain key
        key = domain.strip().lower()
        if key in self._domain_cache:
            return self._domain_cache[key]

        alive = False
        try:
            sysname = platform.system()
            ping_path = shutil.which("ping")
            if ping_path:
                if sysname == "Windows":
                    cmd = [ping_path, "-n", "1", key]
                else:
                    cmd = [ping_path, "-c", "1", key]
                try:
                    # Use process timeout to bound execution time
                    res = subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=1.5,
                        check=False,
                    )
                    alive = res.returncode == 0
                except subprocess.TimeoutExpired:
                    alive = False
            # Fallback to TCP connect if ping missing or failed
            if not alive:
                try:
                    with socket.create_connection((key, 80), timeout=1.0):
                        alive = True
                except Exception:
                    alive = False
        except Exception:
            alive = False

        self._domain_cache[key] = alive
        return alive

    def _tld_is_valid(self, domain: str) -> bool:
        """Check if domain has a valid TLD per provided list."""
        try:
            d = domain.strip().lower().rstrip(".")
            # Extract last label after final dot
            if "." not in d:
                return False
            last = d.rsplit(".", 1)[-1]
            tld = "." + last
            return tld in VALID_TLDS
        except Exception:
            return False


class IoCNinjaWidget(QWidget):
    def __init__(self, parent: QWidget, name: str, bv: BinaryView):
        super().__init__(parent)
        self.bv = bv
        self._thread = None
        self._worker = None
        self._start_time = 0.0

        # Display name overrides for IoC types
        self._type_display = {
            "OpenAI_SG": "OpenAI API Key",
        }

        # Left panel: IoC type filters (categorized) as a two-column tree: [checkbox][name]
        self.ioc_tree = QTreeWidget()
        self.ioc_tree.setColumnCount(2)
        self.ioc_tree.setHeaderLabels(["", "Type"])
        self.ioc_tree.setRootIsDecorated(True)
        # No zebra color for IoC tree
        self.ioc_tree.setAlternatingRowColors(False)
        self.ioc_tree.setUniformRowHeights(True)
        self.ioc_tree.setIndentation(20)
        # Column sizing: checkbox column auto, name stretches
        self.ioc_tree.header().setVisible(False)
        self.ioc_tree.header().setStretchLastSection(True)
        try:
            self.ioc_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.ioc_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        except Exception:
            pass
        # Build a two-column table to render checkboxes and names without overlap
        self.ioc_table = QTableWidget()
        self.ioc_table.setColumnCount(1)
        self.ioc_table.setShowGrid(False)
        self.ioc_table.setAlternatingRowColors(False)
        self.ioc_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.ioc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ioc_table.verticalHeader().setVisible(False)
        self.ioc_table.horizontalHeader().setVisible(False)
        self.ioc_table.setWordWrap(False)
        # Make rows feel less cramped
        self.ioc_table.setFocusPolicy(Qt.NoFocus)
        self.ioc_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        try:
            self.ioc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        except Exception:
            pass

        # Category mapping and order
        category_map = {
            "IPv4": "Network",
            "IPv6": "Network",
            "Domain": "Network",
            "URL": "Network",
            "Email": "Network",
            "UserAgent_hdr": "Network Headers",
            "WinPath": "Files & Registry",
            "UnixPath": "Files & Registry",
            "Registry": "Files & Registry",
            "MD5": "Hashes",
            "SHA1": "Hashes",
            "SHA256": "Hashes",
            "UUID": "Identifiers",
            "MAC": "Identifiers",
            "JWT": "Tokens & Keys",
            "AWS_AK": "Tokens & Keys",
            "Google_API": "Tokens & Keys",
            "OpenAI_SG": "Tokens & Keys",
            "RSA_PEM": "Tokens & Keys",
            "RSA_PUB_PEM": "Tokens & Keys",
            "Process_or_Command": "Execution",
            "Mutex": "Execution",
            "XOR_or_ROT_keyword": "Execution",
            "Base64_block": "Encodings",
        }
        categories_order = [
            "Network",
            "Network Headers",
            "Files & Registry",
            "Hashes",
            "Identifiers",
            "Tokens & Keys",
            "Execution",
            "Encodings",
            "Others",
        ]

        # Group keys by category
        by_cat = {c: [] for c in categories_order}
        for key in sorted(ioc_logic.IOC_PATTERNS.keys()):
            cat = category_map.get(key, "Others")
            by_cat.setdefault(cat, []).append(key)

        # Build the IoC selector as a simple two-column table
        row_index = 0
        header_font = QFont(self.font())
        header_font.setBold(True)
        for cat in categories_order:
            keys = sorted(by_cat.get(cat) or [])
            if not keys:
                continue
            # Category header (single column)
            self.ioc_table.insertRow(row_index)
            header_item = QTableWidgetItem(cat)
            header_item.setFont(header_font)
            header_item.setFlags(Qt.ItemIsEnabled)
            header_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.ioc_table.setItem(row_index, 0, header_item)
            self.ioc_table.setRowHeight(row_index, 28)
            row_index += 1
            # Child rows: checkbox + name
            for ioc_type in keys:
                display_name = self._type_display.get(ioc_type, ioc_type.replace("_", " "))
                self.ioc_table.insertRow(row_index)
                # Build a single-cell widget with checkbox + label
                cb = QCheckBox()
                cb.setProperty("ioc_key", ioc_type)
                cb.setChecked(False)
                name_lbl = QLabel(display_name)
                name_lbl.setTextInteractionFlags(Qt.NoTextInteraction)
                cell = QWidget()
                lay = QHBoxLayout(cell)
                # Add breathing room: larger left/right and top/bottom margins
                lay.setContentsMargins(10, 4, 8, 4)
                lay.setSpacing(10)
                lay.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                lay.addWidget(cb)
                lay.addWidget(name_lbl, 1)
                self.ioc_table.setCellWidget(row_index, 0, cell)
                self.ioc_table.setRowHeight(row_index, 28)
                row_index += 1

        # Select all/none controls (will be placed in top controls row)
        self.btn_select_all = QPushButton("All")
        self.btn_select_none = QPushButton("None")
        self.btn_select_all.clicked.connect(lambda: self._set_all_checkboxes(True))
        self.btn_select_none.clicked.connect(lambda: self._set_all_checkboxes(False))
        # Tree handles its own scrolling and layout; no extra stretch needed here

        # Left side: title + scrollable checkbox list
        self.left_panel = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_title = QLabel("IoC Types")
        # Title row with All/None aligned to the right of the title
        self.title_row = QHBoxLayout()
        # Remove inner margins to line up with right controls row
        self.title_row.setContentsMargins(0, 0, 0, 0)
        self.title_row.addWidget(self.left_title)
        self.title_row.addStretch(1)
        self.title_row.addWidget(self.btn_select_all)
        self.title_row.addWidget(self.btn_select_none)
        self.left_layout.addLayout(self.title_row)
        # Add a larger inner margin for better padding
        self.left_layout.setContentsMargins(16, 16, 16, 16)

        # Use the IoC table directly (it scrolls itself)
        self.left_layout.addWidget(self.ioc_table)
        self.left_panel.setLayout(self.left_layout)
        # Default: none checked

        # Top controls for results
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Type/Value/Address")
        self.search_edit.textChanged.connect(self.apply_filter)

        self.btn_scan = QPushButton("Scan")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_clear = QPushButton("Clear")
        self.btn_export = QPushButton("Export")

        self.btn_scan.clicked.connect(self.scan)
        self.btn_cancel.clicked.connect(self.cancel_scan)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_export.clicked.connect(self.choose_export)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.addWidget(self.btn_scan)
        controls.addWidget(self.btn_cancel)
        controls.addWidget(self.btn_clear)
        controls.addStretch(1)
        controls.addWidget(QLabel("Search:"))
        controls.addWidget(self.search_edit)
        controls.addWidget(self.btn_export)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Type", "Value", "Address"])
        # Allow user to adjust column widths interactively
        self.results_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive
        )
        # Ensure table visually uses full available width by stretching last column
        self.results_table.horizontalHeader().setStretchLastSection(True)
        # Encourage the table to expand to fill the right panel
        self.results_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Show full content: no ellipsis and allow wrapping
        self.results_table.setTextElideMode(Qt.ElideNone)
        self.results_table.setWordWrap(True)
        # Apply zebra color to output table for readability
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSortingEnabled(True)
        self.results_table.itemDoubleClicked.connect(self.goto_address_from_item)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._open_context_menu)

        # Status row
        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        self.status_label = QLabel("Ready")
        status = QHBoxLayout()
        status.addWidget(self.progress)
        status.addWidget(self.status_label)
        status.addStretch(1)

        # Right side layout (controls + table + status)
        right = QWidget()
        right_layout = QVBoxLayout()
        right_layout.addLayout(controls)
        right_layout.addWidget(self.results_table)
        right_layout.addLayout(status)
        right.setLayout(right_layout)

        # Splitter between left filters and right results
        self.splitter = QSplitter()
        self.splitter.setChildrenCollapsible(False)
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(right)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)

        outer = QVBoxLayout()
        outer.addWidget(self.splitter)
        self.setLayout(outer)

        # Initial state
        self._set_scanning(False)
        # Adjust left sidebar width to fit the longest text + padding
        self._update_left_sidebar_width()
        # Track whether we already auto-sized columns to content once
        self._columns_sized = False
        # Make All/None the same height as Scan for visual consistency
        try:
            h = self.btn_scan.sizeHint().height()
            self.btn_select_all.setFixedHeight(h)
            self.btn_select_none.setFixedHeight(h)
        except Exception:
            pass

    # Tree-based handlers removed after redesign to table-based selector

    def closeEvent(self, event):
        """Ensure background scan thread is stopped when the tab closes."""
        try:
            if self._worker:
                self._worker.cancel()
            if self._thread:
                self._thread.quit()
                self._thread.wait(1000)
        except Exception:
            pass
        super().closeEvent(event)

    def _set_all_checkboxes(self, value: bool):
        # Toggle all IoC checkboxes in the table
        for r in range(self.ioc_table.rowCount()):
            w = self.ioc_table.cellWidget(r, 0)
            if not w:
                continue
            cb = w.findChild(QCheckBox)
            if cb:
                cb.setChecked(value)

    def _gather_selected_patterns(self):
        selected = {}
        for r in range(self.ioc_table.rowCount()):
            w = self.ioc_table.cellWidget(r, 0)
            if not w:
                continue
            cb = w.findChild(QCheckBox)
            if cb and cb.isChecked():
                key = cb.property("ioc_key")
                if key in ioc_logic.IOC_PATTERNS:
                    selected[key] = ioc_logic.IOC_PATTERNS[key]
        return selected

    def _set_scanning(self, scanning: bool):
        self.btn_scan.setEnabled(not scanning)
        self.btn_cancel.setEnabled(scanning)
        self.btn_clear.setEnabled(not scanning)
        has_rows = self.results_table.rowCount() > 0
        self.btn_export.setEnabled(not scanning and has_rows)
        if scanning:
            # Set to busy until we get the first progress event (which sets max/value)
            self.progress.setMaximum(0)
        else:
            # Determinate mode; caller should set final value explicitly
            self.progress.setMaximum(100)

    def scan(self):
        # Clear previous and start threaded scan
        self.clear_results()
        patterns = self._gather_selected_patterns()
        if not patterns:
            log_info("No IoC types selected.")
            self.status_label.setText("No IoC types selected.")
            return
        self._set_scanning(True)
        self.status_label.setText("Scanning...")
        self._start_time = time.time()

        self._thread = QThread(self)
        self._worker = IoCScanWorker(self.bv, patterns)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.partial.connect(self._on_partial)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.canceled.connect(self._on_canceled)
        self._thread.start()

    def cancel_scan(self):
        if self._worker:
            self._worker.cancel()

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.status_label.setText("Ready")
        self.apply_filter()
        self._columns_sized = False

    def _upsert_row(self, ioc_type: str, value: str, addr_str: str):
        # Update row if Type+Value exists; else insert a new row.
        # For display, replace underscores with spaces in type column
        ioc_type_disp = self._type_display.get(ioc_type, ioc_type.replace("_", " ")) if ioc_type else ioc_type
        rows = self.results_table.rowCount()
        target_row = -1
        for r in range(rows):
            t_item = self.results_table.item(r, 0)
            v_item = self.results_table.item(r, 1)
            if (
                t_item
                and v_item
                and t_item.text() == ioc_type_disp
                and v_item.text() == value
            ):
                target_row = r
                break
        if target_row == -1:
            target_row = rows
            self.results_table.insertRow(target_row)
            self.results_table.setItem(target_row, 0, QTableWidgetItem(ioc_type_disp))
            self.results_table.setItem(target_row, 1, QTableWidgetItem(value))
        self.results_table.setItem(target_row, 2, QTableWidgetItem(addr_str))
        return target_row

    def _on_partial(self, rows):
        # rows: list[(Type, Value, AddressCombined)]
        sorting = self.results_table.isSortingEnabled()
        if sorting:
            self.results_table.setSortingEnabled(False)
        updated_rows = set()
        try:
            for ioc_type, value, addr_str in rows:
                r = self._upsert_row(ioc_type, value, addr_str)
                updated_rows.add(r)
        finally:
            if sorting:
                self.results_table.setSortingEnabled(True)
        # Resize only the rows that changed to reveal wrapped content
        for r in updated_rows:
            if r >= 0:
                self.results_table.resizeRowToContents(r)
        # On first data arrival, auto size columns to contents then keep interactive
        if not self._columns_sized and self.results_table.rowCount() > 0:
            self._init_column_sizes()
        self.apply_filter()

    def export_csv(self):
        if self.results_table.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "ioc_results.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Value", "Address"])
                for r in range(self.results_table.rowCount()):
                    type_item = self.results_table.item(r, 0)
                    value_item = self.results_table.item(r, 1)
                    addr_item = self.results_table.item(r, 2)
                    writer.writerow(
                        [
                            type_item.text() if type_item else "",
                            value_item.text() if value_item else "",
                            addr_item.text() if addr_item else "",
                        ]
                    )
            self.status_label.setText(f"Exported to {path}")
        except Exception as e:
            self.status_label.setText(f"Export failed: {e}")

    def choose_export(self):
        if self.results_table.rowCount() == 0:
            return
        # Pop up menu with export/copy formats
        menu = QMenu(self)
        act_csv = QAction("Export as CSV", self)
        act_md_bullet = QAction("Export as Markdown Bullet List", self)
        act_md_table = QAction("Export as Markdown Table", self)
        act_copy_md_bullet = QAction("Copy as Markdown Bullet List", self)
        act_copy_md_table = QAction("Copy as Markdown Table", self)

        menu.addAction(act_csv)
        menu.addSeparator()
        menu.addAction(act_md_bullet)
        menu.addAction(act_md_table)
        menu.addSeparator()
        menu.addAction(act_copy_md_bullet)
        menu.addAction(act_copy_md_table)

        act_csv.triggered.connect(self.export_csv)
        act_md_bullet.triggered.connect(self.export_markdown_bullet)
        act_md_table.triggered.connect(self.export_markdown_table)
        act_copy_md_bullet.triggered.connect(self.copy_markdown_bullet)
        act_copy_md_table.triggered.connect(self.copy_markdown_table)

        menu.exec(self.btn_export.mapToGlobal(self.btn_export.rect().bottomLeft()))

    def _collect_rows(self):
        rows = []
        for r in range(self.results_table.rowCount()):
            type_item = self.results_table.item(r, 0)
            value_item = self.results_table.item(r, 1)
            addr_item = self.results_table.item(r, 2)
            rows.append(
                [
                    type_item.text() if type_item else "",
                    value_item.text() if value_item else "",
                    addr_item.text() if addr_item else "",
                ]
            )
        return rows

    def export_markdown_bullet(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Markdown", "ioc_results.md", "Markdown Files (*.md)"
        )
        if not path:
            return
        try:
            md = self._render_md_bullet()
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            self.status_label.setText(f"Exported to {path}")
        except Exception as e:
            self.status_label.setText(f"Export failed: {e}")

    def export_markdown_table(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Markdown", "ioc_results.md", "Markdown Files (*.md)"
        )
        if not path:
            return
        try:
            md = self._render_md_table()
            with open(path, "w", encoding="utf-8") as f:
                f.write(md)
            self.status_label.setText(f"Exported to {path}")
        except Exception as e:
            self.status_label.setText(f"Export failed: {e}")

    def copy_markdown_bullet(self):
        try:
            md = self._render_md_bullet()
            from PySide6.QtWidgets import QApplication

            QApplication.instance().clipboard().setText(md)
            self.status_label.setText("Copied Markdown bullet list to clipboard")
        except Exception as e:
            self.status_label.setText(f"Copy failed: {e}")

    def copy_markdown_table(self):
        try:
            md = self._render_md_table()
            from PySide6.QtWidgets import QApplication

            QApplication.instance().clipboard().setText(md)
            self.status_label.setText("Copied Markdown table to clipboard")
        except Exception as e:
            self.status_label.setText(f"Copy failed: {e}")

    def _render_md_bullet(self) -> str:
        grouped = {}
        for t, v, _a in self._collect_rows():
            t = t.strip()
            v = v.strip()
            if not t:
                continue
            grouped.setdefault(t, set()).add(v)
        lines = []
        for t in sorted(grouped.keys()):
            lines.append(f"- {t}")
            for v in sorted([vv for vv in grouped[t] if vv]):
                lines.append(f"    - {v}")
        return "\n".join(lines) + "\n"

    def _render_md_table(self) -> str:
        def esc(s: str) -> str:
            # Escape pipe to avoid breaking table cells
            return s.replace("|", "\\|") if s else s

        rows = self._collect_rows()
        lines = ["| Type | Value | Address |", "| --- | --- | --- |"]
        for t, v, a in rows:
            lines.append(f"| {esc(t)} | {esc(v)} | {esc(a)} |")
        return "\n".join(lines) + "\n"

    def apply_filter(self):
        text = self.search_edit.text().strip().lower()
        rows = self.results_table.rowCount()
        for r in range(rows):
            show = True
            if text:
                parts = []
                for c in range(self.results_table.columnCount()):
                    item = self.results_table.item(r, c)
                    parts.append(item.text().lower() if item else "")
                hay = " \t".join(parts)
                show = text in hay
            self.results_table.setRowHidden(r, not show)

    def _on_progress(self, processed: int, total: int):
        # Switch to determinate mode and reflect actual progress
        self.progress.setMaximum(total if total > 0 else 1)
        self.progress.setValue(min(processed, total if total > 0 else processed))
        elapsed = time.time() - self._start_time if self._start_time else 0
        self.status_label.setText(
            f"Scanning: {processed}/{total} strings | Elapsed {elapsed:.1f}s"
        )

    def _update_left_sidebar_width(self):
        # Compute minimum width to fit all tree item texts and the title, with padding
        try:
            # Estimate width from IoC table's text column
            fm = (
                self.ioc_table.fontMetrics()
                if hasattr(self, "ioc_table")
                else self.fontMetrics()
            )
            max_item_w = 0
            if hasattr(self, "ioc_table"):
                for r in range(self.ioc_table.rowCount()):
                    # Prefer the name column (1); for category rows, text sits in column 0
                    item1 = self.ioc_table.item(r, 1)
                    item0 = self.ioc_table.item(r, 0)
                    txt_w = 0
                    if item1:
                        txt_w = fm.horizontalAdvance(item1.text())
                    elif item0:
                        txt_w = fm.horizontalAdvance(item0.text())
                    max_item_w = max(max_item_w, txt_w)
            title_w = (
                self.left_title.sizeHint().width() if hasattr(self, "left_title") else 0
            )
            # Title row includes the title and All/None buttons
            all_w = (
                self.btn_select_all.sizeHint().width()
                if hasattr(self, "btn_select_all")
                else 0
            )
            none_w = (
                self.btn_select_none.sizeHint().width()
                if hasattr(self, "btn_select_none")
                else 0
            )
            row_spacing = (
                self.title_row.spacing()
                if hasattr(self, "title_row")
                else (self.left_layout.spacing() if hasattr(self, "left_layout") else 6)
            )
            title_row_required = title_w + all_w + none_w + row_spacing
            # Account for vertical scrollbar eating viewport width when present
            try:
                from PySide6.QtWidgets import QApplication

                sb_w = (
                    QApplication.instance()
                    .style()
                    .pixelMetric(QStyle.PM_ScrollBarExtent)
                )
            except Exception:
                sb_w = 12
            # Account for in-cell checkbox and padding
            padding_extra = 24
            content_w = max(max_item_w + sb_w + padding_extra, title_row_required)
            # Add inner padding and account for larger layout margins
            padding = 32
            min_w = content_w + padding
            self.left_panel.setMinimumWidth(min_w)
            # Also set initial splitter sizes so right side gets remaining space
            try:
                total_w = self.width() if self.width() > 0 else (min_w + 400)
                self.splitter.setSizes([min_w, max(300, total_w - min_w)])
            except Exception:
                pass
        except Exception:
            # In case size hints are not ready, fall back to a reasonable default
            self.left_panel.setMinimumWidth(220)

    def _teardown_thread(self):
        if self._worker:
            self._worker.progress.disconnect()
            try:
                self._worker.partial.disconnect()
            except Exception:
                pass
            self._worker.finished.disconnect()
            self._worker.failed.disconnect()
            self._worker.canceled.disconnect()
        if self._thread:
            self._thread.quit()
            self._thread.wait(2000)
        self._worker = None
        self._thread = None

    def _on_finished(self, results, scanned, elapsed):
        # Always upsert final results to ensure anything not emitted via partial (e.g., file hashes) appears.
        sorting = self.results_table.isSortingEnabled()
        if sorting:
            self.results_table.setSortingEnabled(False)
        try:
            for ioc_type, value, addr_str in results:
                self._upsert_row(ioc_type, value, addr_str)
        finally:
            if sorting:
                self.results_table.setSortingEnabled(True)
        self.apply_filter()
        # Resize all rows to fit wrapped text
        self.results_table.resizeRowsToContents()
        # Auto size columns to contents once
        if not self._columns_sized and self.results_table.rowCount() > 0:
            self._init_column_sizes()
        # Reflect completion on progress bar
        self.progress.setMaximum(100)
        self.progress.setValue(100)
        self.status_label.setText(
            f"Findings: {len(results)} | Strings Scanned: {scanned} | Elapsed {elapsed:.1f}s"
        )
        self._set_scanning(False)
        self._teardown_thread()

    def _on_failed(self, msg: str):
        self.status_label.setText(f"Scan failed: {msg}")
        self._set_scanning(False)
        self._teardown_thread()

    def _on_canceled(self):
        self.status_label.setText("Scan canceled")
        self._set_scanning(False)
        self._teardown_thread()

    def _open_context_menu(self, pos):
        menu = QMenu(self)
        act_copy_value = QAction("Copy Value", self)
        act_copy_addr = QAction("Copy Address(es)", self)
        act_copy_row = QAction("Copy Row (CSV)", self)
        menu.addAction(act_copy_value)
        menu.addAction(act_copy_addr)
        menu.addAction(act_copy_row)
        menu.addSeparator()

        idx = self.results_table.indexAt(pos)
        row = idx.row()

        def get_item(c):
            item = self.results_table.item(row, c)
            return item.text() if item else ""

        def copy_text(txt):
            # Use Qt clipboard to avoid external deps
            from PySide6.QtWidgets import QApplication

            cb = QApplication.instance().clipboard()
            cb.setText(txt)

        # Navigation submenu for potentially multiple addresses
        addresses_text = get_item(2)
        addresses = self._parse_addresses(addresses_text)
        if addresses:
            if len(addresses) == 1:
                act_nav_single = QAction(f"Navigate to {addresses[0]}", self)
                menu.addAction(act_nav_single)
                act_nav_single.triggered.connect(
                    lambda: self.goto_address_text(addresses[0])
                )
            else:
                nav_menu = QMenu("Navigate to Address", self)
                for a in addresses:
                    act = QAction(a, self)
                    act.triggered.connect(
                        lambda checked=False, aa=a: self.goto_address_text(aa)
                    )
                    nav_menu.addAction(act)
                menu.addMenu(nav_menu)

        act_copy_value.triggered.connect(lambda: copy_text(get_item(1)))
        act_copy_addr.triggered.connect(lambda: copy_text(get_item(2)))
        act_copy_row.triggered.connect(
            lambda: copy_text(f"{get_item(0)},{get_item(1)},{get_item(2)}")
        )

        menu.exec(self.results_table.viewport().mapToGlobal(pos))

    def _init_column_sizes(self):
        try:
            header = self.results_table.horizontalHeader()
            # Temporarily set to ResizeToContents to compute widths
            for c in range(self.results_table.columnCount()):
                header.setSectionResizeMode(c, QHeaderView.ResizeToContents)
            self.results_table.resizeColumnsToContents()
            # Restore interactive so user can adjust manually afterwards
            for c in range(self.results_table.columnCount()):
                header.setSectionResizeMode(c, QHeaderView.Interactive)
            self._columns_sized = True
        except Exception:
            self._columns_sized = True

    def goto_address_from_item(self, item):
        # Navigate: if multiple addresses, prompt a small chooser
        row = item.row()
        addr_item = self.results_table.item(row, 2)
        if not addr_item:
            return
        addrs = self._parse_addresses(addr_item.text())
        if not addrs:
            return
        if len(addrs) == 1:
            self.goto_address_text(addrs[0])
            return
        # Multiple: show quick menu at cursor for selection
        menu = QMenu(self)
        for a in addrs:
            act = QAction(a, self)
            act.triggered.connect(
                lambda checked=False, aa=a: self.goto_address_text(aa)
            )
            menu.addAction(act)
        # Use global cursor position to place menu
        from PySide6.QtGui import QCursor

        menu.exec(QCursor.pos())

    def goto_address_text(self, addr_str: str):
        if addr_str == "N/A":
            return
        try:
            addr = int(addr_str, 16)
            self.bv.navigate(self.bv.view, addr)
        except ValueError:
            log_info(f"Invalid address: {addr_str}")

    def _parse_addresses(self, text: str):
        """Parse a combined address string into a list of hex strings.
        Accepts comma or whitespace separated hex values, ignores 'N/A'."""
        if not text:
            return []
        parts = [p.strip() for p in re.split(r"[,\s]+", text) if p.strip()]
        addrs = []
        for p in parts:
            if p.upper() == "N/A":
                continue
            # basic validation of hex string
            try:
                _ = int(p, 16)
                addrs.append(p)
            except Exception:
                continue
        # De-duplicate while preserving order
        seen = set()
        uniq = []
        for a in addrs:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        return uniq
