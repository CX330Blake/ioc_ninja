from binaryninja.binaryview import BinaryView
from binaryninja.log import log_info
import time
import csv
import re

from PySide6.QtGui import QAction, QFont, QColor, QPalette, QPainter, QPen
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QCheckBox,
    QPushButton,
    QComboBox,
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
    QProxyStyle,
    QDialog,
    QDialogButtonBox,
)
from PySide6.QtCore import Qt, QObject, QThread, Signal, QEvent, QSettings
import os

# Adjusted imports for package layout: logic is sibling package under top-level package
from ..logic import ioc_logic
from ..tld_data import VALID_TLDS

import platform
# Register plugin settings with Binary Ninja so options appear in the application's Settings (user scope).
try:
    from binaryninja.settings import Settings as _BNSettings
    from binaryninja import settings as _bn_settings_mod
    from binaryninja.enums import SettingsScope as _SettingsScope
    _bn_settings = _BNSettings()
    # Create a top-level group for IoC Ninja and register the user-scoped boolean setting.
    _bn_settings.register_group("iocninja", "IoC Ninja")
    _bn_settings.register_setting(
        "iocninja.resolvable_domains_only",
        '{"title":"Resolvable domains only (DNS)", "description":"Resolve domains via DNS after scanning; filter out unresolvable domains.", "type":"boolean", "default": false, "ignore": ["SettingsProjectScope","SettingsResourceScope"]}'
    )
except Exception:
    _bn_settings = None
import socket
import hashlib

class IoCCheckboxProxyStyle(QProxyStyle):
    """Custom checkbox style that draws border with CommentColor and check mark with Text color.
    Colors are read from widget properties 'ioc_border_qcolor' and 'ioc_tick_qcolor' (QColor),
    with fallbacks to the widget palette.
    """

    def drawPrimitive(self, element, option, painter, widget=None):
        if element == QStyle.PE_IndicatorCheckBox and widget is not None:
            try:
                rect = option.rect
                # Resolve colors
                border = widget.property("ioc_border_qcolor")
                if not isinstance(border, QColor):
                    border = widget.palette().mid().color()
                tick = widget.property("ioc_tick_qcolor")
                if not isinstance(tick, QColor):
                    tick = widget.palette().windowText().color()

                # Draw border box (square corners)
                painter.save()
                painter.setRenderHint(QPainter.Antialiasing, True)
                painter.setPen(QPen(border, 1))
                painter.setBrush(Qt.NoBrush)
                r = rect.adjusted(1, 1, -1, -1)
                painter.drawRect(r)

                # Draw check mark if checked or partially checked
                if (
                    option.state & QStyle.State_On
                    or option.state & QStyle.State_NoChange
                ):
                    painter.setPen(QPen(tick, 2))
                    # Simple check mark geometry
                    x1 = r.left() + int(r.width() * 0.18)
                    y1 = r.top() + int(r.height() * 0.55)
                    x2 = r.left() + int(r.width() * 0.44)
                    y2 = r.top() + int(r.height() * 0.80)
                    x3 = r.left() + int(r.width() * 0.82)
                    y3 = r.top() + int(r.height() * 0.28)
                    painter.drawLine(x1, y1, x2, y2)
                    painter.drawLine(x2, y2, x3, y3)
                painter.restore()
                return
            except Exception:
                pass
        # Fallback to default rendering
        return super().drawPrimitive(element, option, painter, widget)

class IoCScanWorker(QObject):
    """Background worker to scan strings with progress and cancel."""

    progress = Signal(int, int)  # processed, total
    partial = Signal(list)  # list of (Type, Value, AddressCombined)
    finished = Signal(list, int, float)  # results, scanned_count, elapsed
    failed = Signal(str)
    canceled = Signal()

    def __init__(self, bv: BinaryView, patterns, filter_live_domains: bool = False):
        super().__init__()
        self.bv = bv
        self.patterns = patterns
        self.filter_live_domains = bool(filter_live_domains)
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
            if self.patterns and any(
                t in self.patterns for t in ("MD5", "SHA1", "SHA256")
            ):
                try:
                    f = getattr(self.bv, "file", None)
                    if f is not None:
                        if "MD5" in self.patterns:
                            md5 = getattr(f, "md5", None)
                            if md5:
                                agg.setdefault(("MD5", md5), set()).add("N/A")
                        if "SHA1" in self.patterns:
                            sha1 = getattr(f, "sha1", None)
                            if sha1:
                                agg.setdefault(("SHA1", sha1), set()).add("N/A")
                        if "SHA256" in self.patterns:
                            sha256 = getattr(f, "sha256", None)
                            if sha256:
                                agg.setdefault(("SHA256", sha256), set()).add("N/A")
                except Exception:
                    pass
                # If API did not yield hashes, fall back to hashing bytes once
                if ("MD5",) or ("SHA1",) or ("SHA256",):
                    need_md5 = ("MD5" in self.patterns) and not any(
                        k[0] == "MD5" for k in agg.keys()
                    )
                    need_sha1 = ("SHA1" in self.patterns) and not any(
                        k[0] == "SHA1" for k in agg.keys()
                    )
                    need_sha256 = ("SHA256" in self.patterns) and not any(
                        k[0] == "SHA256" for k in agg.keys()
                    )
                    if need_md5 or need_sha1 or need_sha256:
                        try:
                            data = b""
                            length = getattr(self.bv, "end", None)
                            if length:
                                data = self.bv.read(0, int(length)) or b""
                            if (
                                not data
                                and hasattr(self.bv, "parent_view")
                                and hasattr(self.bv.parent_view, "end")
                            ):
                                data = (
                                    self.bv.parent_view.read(
                                        0, int(self.bv.parent_view.end)
                                    )
                                    or b""
                                )
                            if data:
                                if need_md5:
                                    agg.setdefault(
                                        ("MD5", hashlib.md5(data).hexdigest()), set()
                                    ).add("N/A")
                                if need_sha1:
                                    agg.setdefault(
                                        ("SHA1", hashlib.sha1(data).hexdigest()), set()
                                    ).add("N/A")
                                if need_sha256:
                                    agg.setdefault(
                                        ("SHA256", hashlib.sha256(data).hexdigest()),
                                        set(),
                                    ).add("N/A")
                        except Exception:
                            pass
            processed = 0
            # Throttle progress updates for smoother, linear growth without UI spam
            last_prog_ts = start
            last_prog_count = 0
            PROG_MIN_INTERVAL = 0.03  # seconds between progress signals (~30 FPS)
            PROG_MIN_STEP = 5         # or every N items, whichever first
            # When live domain filtering is enabled, defer network checks and suppress domain partials
            pending_domains: dict[tuple, set] = {}
            domains_to_check: set[str] = set()
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
                            if k == "Domain":
                                if not self._tld_is_valid(v):
                                    continue
                                if self.filter_live_domains:
                                    dkey = v.strip().lower()
                                    domains_to_check.add(dkey)
                                    addr_str_pd = (
                                        hex(addr) if isinstance(addr, int) else "N/A"
                                    )
                                    pending_domains.setdefault((k, v), set()).add(
                                        addr_str_pd
                                    )
                                    # Skip adding to agg now; we'll add alive domains later
                                    continue
                                else:
                                    # Without live filtering: keep previous fast behavior (DNS only)
                                    if not self._domain_resolves(v):
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
                            # Suppress domain partials when filter_live_domains is True
                            if self.filter_live_domains and ioc_type == "Domain":
                                continue
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
                # Emit progress more frequently for smoother bar growth
                now = time.time()
                if (
                    (now - last_prog_ts) >= PROG_MIN_INTERVAL
                    or (processed - last_prog_count) >= PROG_MIN_STEP
                    or processed == total
                ):
                    self.progress.emit(processed, total)
                    last_prog_ts = now
                    last_prog_count = processed
            # If live filtering is requested, process domains concurrently and then merge those deemed alive
            if self.filter_live_domains and domains_to_check:
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed

                    max_workers = min(8, max(2, (os.cpu_count() or 2)))
                    with ThreadPoolExecutor(max_workers=max_workers) as pool:
                        fut_map = {
                            pool.submit(self._domain_resolves, d): d
                            for d in domains_to_check
                        }
                        for fut in as_completed(fut_map):
                            if self._cancel:
                                self.canceled.emit()
                                return
                            d = fut_map[fut]
                            ok = False
                            try:
                                ok = bool(fut.result())
                            except Exception:
                                ok = False
                            if ok:
                                # Merge any pending records for this domain
                                for (k, v), addrs in list(pending_domains.items()):
                                    if v.strip().lower() == d:
                                        b = agg.setdefault((k, v), set())
                                        before = len(b)
                                        b.update(addrs)
                                        if len(b) != before:
                                            self._changed_keys.add((k, v))
                                        del pending_domains[(k, v)]
                except Exception:
                    # Fallback sequential
                    for d in list(domains_to_check):
                        if self._cancel:
                            self.canceled.emit()
                            return
                        if self._domain_resolves(d):
                            for (k, v), addrs in list(pending_domains.items()):
                                if v.strip().lower() == d:
                                    b = agg.setdefault((k, v), set())
                                    b.update(addrs)
                                    self._changed_keys.add((k, v))
                                    del pending_domains[(k, v)]
                # Emit a final partial for domains now added
                if self._changed_keys:
                    partial_rows = []
                    for ioc_type, value in sorted(
                        self._changed_keys, key=lambda x: (x[0], x[1])
                    ):
                        addrs = agg.get((ioc_type, value), set())
                        numeric_addrs = sorted(
                            [a for a in addrs if a != "N/A"], key=lambda x: int(x, 16)
                        )
                        if "N/A" in addrs:
                            numeric_addrs.append("N/A")
                        addr_join = ", ".join(numeric_addrs)
                        partial_rows.append((ioc_type, value, addr_join))
                    if partial_rows:
                        self.partial.emit(partial_rows)
                        self._changed_keys.clear()
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

    def _domain_resolves(self, domain: str) -> bool:
        """Fast DNS reachability check with caching.
        Returns True if the domain resolves to at least one address via getaddrinfo/gethostbyname.
        Does not perform ICMP ping or TCP connect.
        """
        # Normalize domain key
        key = domain.strip().lower()
        if key in self._domain_cache:
            return self._domain_cache[key]

        alive = False
        try:
            # Try DNS resolution via getaddrinfo
            try:
                infos = socket.getaddrinfo(key, None)
                if infos:
                    alive = True
            except Exception:
                alive = False
            # Fallback: gethostbyname_ex
            if not alive:
                try:
                    _h, _a, addrs = socket.gethostbyname_ex(key)
                    alive = bool(addrs)
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
        self._accent_qcolor = self._resolve_accent_color()
        self._progress_chunk_color = None  # Will be set in _apply_control_styles()
        # Prepare proxy style for checkboxes
        try:
            self._checkbox_style = IoCCheckboxProxyStyle(self.style())
        except Exception:
            self._checkbox_style = None
        # Binary selection state
        self._bvs_by_name: dict[str, BinaryView] = {}
        self._binary_name_max_chars = (
            24  # max chars to display in combo before ascii "..." elide
        )
        # Settings state
        self._resolvable_only = False
        try:
            # Prefer Binary Ninja's Settings (user scope). Key registered as "iocninja.resolvable_domains_only".
            self._resolvable_only = self._load_setting_bool(
                "iocninja.resolvable_domains_only", False
            )
        except Exception:
            self._resolvable_only = False

        # Display name overrides for IoC types
        self._type_display = {
            "OpenAI_SG": "OpenAI API Key",
            "UserAgent_hdr": "UserAgent Header",
        }

        # Soft-wrap configuration for long, unbroken strings in the Value column
        self._wrap_run_length = (
            16  # insert zero-width space every N chars when no natural breaks
        )

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
        # Make it look/behave like a table (like the right side) but without row grid lines
        self.ioc_table.setShowGrid(False)
        self.ioc_table.setAlternatingRowColors(True)
        self.ioc_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.ioc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.ioc_table.verticalHeader().setVisible(False)
        self.ioc_table.horizontalHeader().setVisible(False)
        self.ioc_table.setWordWrap(False)
        # Make rows feel less cramped
        self.ioc_table.setFocusPolicy(Qt.NoFocus)
        self.ioc_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        try:
            self.ioc_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.Stretch
            )
        except Exception:
            pass
        try:
            self.ioc_table.setGridStyle(Qt.SolidLine)
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
        try:
            if header_font.pointSize() > 0:
                header_font.setPointSize(
                    header_font.pointSize() + 1
                )  # slightly larger than IoC type rows
            else:
                px = header_font.pixelSize()
                header_font.setPixelSize(max(13, (px + 2) if px and px > 0 else 14))
        except Exception:
            pass
        for cat in categories_order:
            keys = sorted(by_cat.get(cat) or [])
            if not keys:
                continue
            # Insert a thin separator line before each category (except the first)
            if row_index > 0:
                self.ioc_table.insertRow(row_index)
                try:
                    sep = self._build_category_separator()
                    self.ioc_table.setCellWidget(row_index, 0, sep)
                    # Center the line by giving the separator its own height and centering the 1px rule inside
                    self.ioc_table.setRowHeight(row_index, sep.height())
                except Exception:
                    # Fallback: a minimal gap
                    self.ioc_table.setRowHeight(row_index, 8)
                row_index += 1
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
                display_name = self._type_display.get(
                    ioc_type, ioc_type.replace("_", " ")
                )
                self.ioc_table.insertRow(row_index)
                # Build a single-cell widget with checkbox + label
                cb = QCheckBox()
                cb.setProperty("ioc_key", ioc_type)
                cb.setChecked(False)
                # Provide colors to proxy style and apply it
                try:
                    cb.setProperty(
                        "ioc_border_qcolor", self._theme_color("CommentColor")
                    )
                    cb.setProperty("ioc_tick_qcolor", self._text_color())
                    if self._checkbox_style is not None:
                        cb.setStyle(self._checkbox_style)
                except Exception:
                    pass
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
                # Keep default Binary Ninja/Qt styling to avoid visual weirdness
                # (Previous custom styling removed per user feedback)
                # Enlarge click target: toggle checkbox when clicking anywhere on the row cell
                try:
                    cell.setProperty("ioc_cb", cb)
                    cell.installEventFilter(self)
                except Exception:
                    pass
                self.ioc_table.setCellWidget(row_index, 0, cell)
                self.ioc_table.setRowHeight(row_index, 28)
                row_index += 1

        # Select all/none controls (will be placed in top controls row)
        self.btn_select_all = QPushButton("✅All")
        self.btn_select_none = QPushButton("❌None")
        self.btn_select_all.clicked.connect(lambda: self._set_all_checkboxes(True))
        self.btn_select_none.clicked.connect(lambda: self._set_all_checkboxes(False))
        # Tree handles its own scrolling and layout; no extra stretch needed here

        # Left side: title + scrollable checkbox list
        self.left_panel = QWidget()
        self.left_layout = QVBoxLayout()
        self.left_title = QLabel("🥷 IoC Ninja")
        # Make the IoC Types title larger and bold
        try:
            title_font = QFont(self.font())
            title_font.setBold(True)
            if title_font.pointSize() > 0:
                title_font.setPointSize(title_font.pointSize() + 2)
            else:
                # Fallback when using pixel-size fonts
                px = title_font.pixelSize()
                title_font.setPixelSize(max(14, (px + 2) if px and px > 0 else 16))
            self.left_title.setFont(title_font)
        except Exception:
            pass
        # Title row with All/None aligned to the right of the title
        self.title_row = QHBoxLayout()
        # Remove inner margins to line up with right controls row
        self.title_row.setContentsMargins(0, 0, 0, 0)
        try:
            self.left_title.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        except Exception:
            pass
        self.title_row.addWidget(self.left_title)
        self.title_row.addStretch(1)
        self.title_row.addWidget(self.btn_select_all)
        self.title_row.addWidget(self.btn_select_none)
        # Wrap title row in a widget so we can control its height to match right side controls row
        self.title_bar = QWidget()
        self.title_bar.setLayout(self.title_row)
        self.left_layout.addWidget(self.title_bar)
        # Remove outer margins to align vertically with right controls row
        self.left_layout.setContentsMargins(0, 0, 0, 0)

        # Wrap the IoC table in a boxed container to guarantee visible padding
        # Container carries the border; inner layout margins are the padding
        try:
            self.ioc_table.setViewportMargins(0, 0, 0, 0)
        except Exception:
            pass
        try:
            self.ioc_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        except Exception:
            pass
        self.ioc_box = QWidget()
        try:
            self.ioc_box.setObjectName("ioc_box")
        except Exception:
            pass
        self.ioc_box_layout = QVBoxLayout()
        # Leave horizontal inset 1px for border visibility, and add vertical padding
        # equal to the visual gap between a divider and the next category title.
        try:
            pad_v = self._category_divider_gap()
        except Exception:
            pad_v = 4
        self.ioc_box_layout.setContentsMargins(1, pad_v, 1, pad_v)
        self.ioc_box_layout.setSpacing(0)
        self.ioc_box_layout.addWidget(self.ioc_table)
        self.ioc_box.setLayout(self.ioc_box_layout)
        try:
            self.ioc_box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        except Exception:
            pass
        self.left_layout.addWidget(self.ioc_box, 1)
        self.left_panel.setLayout(self.left_layout)
        try:
            # Ensure the left panel itself prefers to expand vertically
            self.left_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        except Exception:
            pass
        # Default: none checked

        # Top controls for results
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Type/Value/Address")
        self.search_edit.textChanged.connect(self.apply_filter)

        self.btn_scan = QPushButton("📡Scan")
        self.btn_cancel = QPushButton("✋Cancel")
        try:
            self.btn_cancel.setObjectName("btn_cancel")
        except Exception:
            pass
        self.btn_clear = QPushButton("🧹Clear")
        self.btn_export = QPushButton("📦Export")
        try:
            self.btn_export.setObjectName("btn_export")
        except Exception:
            pass

        self.btn_scan.clicked.connect(self.scan)
        self.btn_cancel.clicked.connect(self.cancel_scan)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_export.clicked.connect(self.choose_export)

        # Install hover cursor behavior for disabled buttons (no style changes)
        try:
            self._install_button_event_filters()
        except Exception:
            pass
        # Override only Cancel's disabled look to match enabled color (no global style changes)
        try:
            self._apply_cancel_disabled_style()
        except Exception:
            pass
        # Override only Export's disabled look to match enabled color (no global style changes)
        try:
            self._apply_export_disabled_style()
        except Exception:
            pass

        # Ensure button text uses theme 'Text' token (or fallback)
        try:
            self._apply_button_text_style()
        except Exception:
            pass

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.addWidget(self.btn_scan)
        controls.addWidget(self.btn_cancel)
        controls.addWidget(self.btn_clear)
        controls.addStretch(1)
        # Binary selector: choose active BinaryView for scanning/navigation
        self.binary_selector = QComboBox()
        try:
            # Prevent long names from overflowing: elide in the middle and cap width
            try:
                self.binary_selector.setElideMode(Qt.ElideMiddle)
            except Exception:
                pass
            try:
                self.binary_selector.setSizeAdjustPolicy(
                    QComboBox.AdjustToMinimumContentsLengthWithIcon
                )
                self.binary_selector.setMinimumContentsLength(24)
            except Exception:
                pass
            try:
                self.binary_selector.setMaximumWidth(320)
            except Exception:
                pass
            # Refresh list on popup to catch newly opened binaries
            try:
                _orig_show = self.binary_selector.showPopup

                def _wrap_show_popup():
                    try:
                        self._setup_binary_selector()
                    except Exception:
                        pass
                    _orig_show()

                self.binary_selector.showPopup = _wrap_show_popup  # type: ignore[assignment]
            except Exception:
                pass
            self._setup_binary_selector()
        except Exception:
            pass
        controls.addWidget(QLabel("Binary:"))
        controls.addWidget(self.binary_selector)
        controls.addWidget(QLabel("Search:"))
        controls.addWidget(self.search_edit)
        controls.addWidget(self.btn_export)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Type", "Value", "Address"])
        # Columns stretch to fill available width; no horizontal scrolling
        try:
            header = self.results_table.horizontalHeader()
            for c in range(3):
                header.setSectionResizeMode(c, QHeaderView.Stretch)
        except Exception:
            pass
        try:
            self.results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        except Exception:
            pass
        # Encourage the table to expand to fill the right panel
        self.results_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Show full content: no ellipsis and allow wrapping
        self.results_table.setTextElideMode(Qt.ElideNone)
        self.results_table.setWordWrap(True)
        # Apply zebra color to output table for readability
        self.results_table.setAlternatingRowColors(True)
        # Render all grid lines (both directions)
        self.results_table.setShowGrid(True)
        try:
            self.results_table.setGridStyle(Qt.SolidLine)
        except Exception:
            pass
        self.results_table.verticalHeader().setVisible(False)
        try:
            self.results_table.verticalHeader().setSectionResizeMode(
                QHeaderView.ResizeToContents
            )
        except Exception:
            pass
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        # Make items unclickable: no selection, no focus, no double-click navigation, no context menu
        self.results_table.setSelectionMode(QAbstractItemView.NoSelection)
        self.results_table.setFocusPolicy(Qt.NoFocus)
        self.results_table.setSortingEnabled(True)
        try:
            self.results_table.itemDoubleClicked.disconnect()
        except Exception:
            pass
        self.results_table.setContextMenuPolicy(Qt.NoContextMenu)
        # Click behavior: copy Value on column 1, navigate on Address column 2
        try:
            self.results_table.itemClicked.connect(self._on_results_item_clicked)
        except Exception:
            pass

        # Status row
        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        try:
            self.progress.setTextVisible(True)
        except Exception:
            pass
        self.status_label = QLabel("Ready")
        status = QHBoxLayout()
        status.addWidget(self.progress)
        status.addWidget(self.status_label)
        status.addStretch(1)

        # Right side layout (controls + table + status)
        right = QWidget()
        right_layout = QVBoxLayout()
        # Match left side: no outer margins so rows start parallel
        right_layout.setContentsMargins(0, 0, 1, 0)
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
            # Ensure the title bar has enough room for the larger title
            th = self.left_title.sizeHint().height()
            self.title_bar.setMinimumHeight(max(h, th))
        except Exception:
            pass

        # No per-row custom styling; rely on platform/BN theme defaults

        # Apply accent styling to progress/search controls
        try:
            self._apply_control_styles()
        except Exception:
            pass
        try:
            self._apply_results_table_style()
        except Exception:
            pass
        # Apply IoC list (left box) border to match output table border color
        try:
            self._apply_ioc_table_style()
        except Exception:
            pass
        # Apply checkbox border color using Binary Ninja CommentColor for all checkboxes in this widget
        try:
            self._apply_checkbox_border_style()
        except Exception:
            pass

    def _open_settings_dialog(self):
        """Open Binary Ninja's Settings UI focused on IoC Ninja if available.
        If BN's UI is unavailable, show an informational dialog explaining where to find the setting.
        """
        try:
            # Try to open Binary Ninja's settings view if the UI binding exposes it.
            try:
                from binaryninjaui import SettingsView  # type: ignore
                sv = SettingsView()
                try:
                    # Try to focus search/filter on our plugin group name if API available
                    sv.setSearchFilter("iocninja")
                except Exception:
                    try:
                        sv.focusSearch()
                    except Exception:
                        pass
                sv.show()
                return
            except Exception:
                pass

            # Fallback: inform user where to find the setting in the application Settings
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.information(
                self,
                "IoC Ninja Settings",
                "IoC Ninja settings moved to Binary Ninja's Settings dialog under the 'IoC Ninja' group.\n\n"
                "Open: Edit → Settings → Plugins → IoC Ninja",
            )
        except Exception:
            pass

    def _load_setting_bool(self, key: str, default: bool = False) -> bool:
        """Load a boolean setting. Prefer Binary Ninja Settings API (user scope), fall back to QSettings."""
        try:
            # Prefer binaryninja.settings module API when available
            try:
                from binaryninja.settings import Settings as _SettingsClass  # type: ignore
                from binaryninja.enums import SettingsScope as _SettingsScope  # type: ignore

                s = _SettingsClass()
                # get_bool_with_scope returns (value, scope)
                try:
                    val, _scope = s.get_bool_with_scope(key, resource=None, scope=_SettingsScope.SettingsUserScope)
                    return bool(val)
                except Exception:
                    # Some BN builds expose get_bool instead; try module-level helper
                    pass
            except Exception:
                pass

            try:
                from binaryninja import settings as _bn_settings_mod  # type: ignore
                from binaryninja.enums import SettingsScope as _SettingsScope  # type: ignore
                try:
                    v = _bn_settings_mod.get_bool_with_scope(key, None, _SettingsScope.SettingsUserScope)
                    # Some module helpers may return a tuple; normalize
                    if isinstance(v, tuple):
                        return bool(v[0])
                    return bool(v)
                except Exception:
                    # Try direct get without scope
                    try:
                        return bool(_bn_settings_mod.get_bool(key))
                    except Exception:
                        pass
            except Exception:
                pass

            # Fallback: QSettings for backward compatibility
            s = QSettings("IoCNinja", "IoCNinja")
            v = s.value(key, defaultValue=default)
            if isinstance(v, bool):
                return v
            return str(v).lower() in ("1", "true", "yes", "on")
        except Exception:
            return default

    def _save_setting_bool(self, key: str, value: bool):
        """Save a boolean setting. Prefer Binary Ninja Settings API (user scope), fall back to QSettings."""
        try:
            try:
                from binaryninja import settings as _bn_settings_mod  # type: ignore
                from binaryninja.enums import SettingsScope as _SettingsScope  # type: ignore
                try:
                    # Module-level helper
                    _bn_settings_mod.set_setting_value(key, bool(value), _SettingsScope.SettingsUserScope)
                    return
                except Exception:
                    pass
                try:
                    s = _bn_settings_mod.Settings()
                    s.set_setting_value(key, bool(value), _SettingsScope.SettingsUserScope)
                    return
                except Exception:
                    pass
            except Exception:
                pass
            # Fallback to local QSettings
            s = QSettings("IoCNinja", "IoCNinja")
            s.setValue(key, bool(value))
        except Exception:
            pass

    def _setup_binary_selector(self):
        """Populate the binary selector with available BinaryViews (best effort).
        Defaults to the current BinaryView; tries to discover others via UI context if available.
        """
        self.binary_selector.clear()
        self._bvs_by_name.clear()

        # Always include current view
        def _bv_display_name(bv: BinaryView) -> str:
            try:
                f = getattr(bv, "file", None)
                n = getattr(f, "original_filename", None)
                if n:
                    return os.path.basename(str(n))
            except Exception:
                pass
            try:
                v = getattr(bv, "view", "Current Binary")
                return os.path.basename(str(v))
            except Exception:
                return "Current Binary"

        try:
            names: list[tuple[str, BinaryView]] = []
            seen_bv_ids: set[int] = set()
            # Always include current view
            if self.bv is not None:
                names.append((_bv_display_name(self.bv), self.bv))
                try:
                    seen_bv_ids.add(id(self.bv))
                except Exception:
                    pass

            # Attempt 1: UIContext view frames (varies by BN build)
            try:
                from binaryninjaui import UIContext  # type: ignore

                ctxs = []
                for meth in ("allContexts", "globalContexts"):
                    if hasattr(UIContext, meth):
                        try:
                            ctxs = list(getattr(UIContext, meth)())
                            break
                        except Exception:
                            ctxs = []
                if not ctxs:
                    c = None
                    try:
                        c = UIContext.activeContext()
                    except Exception:
                        c = None
                    if c:
                        ctxs = [c]
                for ctx in ctxs:
                    frames = []
                    for fmeth in ("getViewFrames", "viewFrames", "getAllViewFrames"):
                        if hasattr(ctx, fmeth):
                            try:
                                frames = list(getattr(ctx, fmeth)())
                                break
                            except Exception:
                                frames = []
                    for vf in frames:
                        bv = None
                        for bv_meth in (
                            "getCurrentBinaryView",
                            "binaryView",
                            "getBinaryView",
                        ):
                            try:
                                attr = getattr(vf, bv_meth)
                                bv = attr() if callable(attr) else attr
                                if isinstance(bv, BinaryView):
                                    break
                            except Exception:
                                continue
                        if bv and isinstance(bv, BinaryView):
                            if id(bv) not in seen_bv_ids:
                                seen_bv_ids.add(id(bv))
                                names.append((_bv_display_name(bv), bv))
            except Exception:
                pass

            # Attempt 2: scan Qt widget tree for objects exposing .binaryView
            try:
                from PySide6.QtWidgets import QApplication

                app = QApplication.instance()
                if app is not None:
                    for tlw in app.topLevelWidgets():
                        try:
                            for obj in tlw.findChildren(object):
                                bv = None
                                for bv_attr in (
                                    "binaryView",
                                    "getBinaryView",
                                    "getCurrentBinaryView",
                                ):
                                    try:
                                        attr = getattr(obj, bv_attr, None)
                                        if callable(attr):
                                            val = attr()
                                        else:
                                            val = attr
                                        if isinstance(val, BinaryView):
                                            bv = val
                                            break
                                    except Exception:
                                        continue
                                if bv and id(bv) not in seen_bv_ids:
                                    seen_bv_ids.add(id(bv))
                                    names.append((_bv_display_name(bv), bv))
                        except Exception:
                            continue
            except Exception:
                pass

            seen = set()
            for disp, bv in names:
                # Apply ASCII middle ellipsis for long names
                shown = self._ellipsize_middle_ascii(disp, self._binary_name_max_chars)
                key = f"{shown}"
                if key in seen:
                    # Disambiguate duplicates
                    idx = 2
                    new_key = f"{shown} ({idx})"
                    while new_key in seen:
                        idx += 1
                        new_key = f"{shown} ({idx})"
                    key = new_key
                seen.add(key)
                self._bvs_by_name[key] = bv
                self.binary_selector.addItem(key)
                try:
                    # Prefer full path in tooltip when available
                    full = None
                    try:
                        f = getattr(bv, "file", None)
                        full = getattr(f, "original_filename", None)
                    except Exception:
                        full = None
                    tooltip = str(full) if full else key
                    self.binary_selector.setItemData(
                        self.binary_selector.count() - 1, tooltip, Qt.ToolTipRole
                    )
                except Exception:
                    pass
            # Select current
            try:
                self.binary_selector.setCurrentIndex(0)
            except Exception:
                pass
            # Wire selection change
            try:
                self.binary_selector.currentTextChanged.connect(self._on_binary_changed)
            except Exception:
                pass
        except Exception:
            # Fallback: single current item
            self._bvs_by_name.clear()
            nm = _bv_display_name(self.bv)
            self._bvs_by_name[nm] = self.bv
            self.binary_selector.addItem(nm)
            try:
                self.binary_selector.setEnabled(False)
            except Exception:
                pass

    def _on_binary_changed(self, name: str):
        """Switch current BinaryView and reset UI state appropriately."""
        try:
            bv = self._bvs_by_name.get(name)
            if not bv or bv is self.bv:
                return
            self.bv = bv
            # Clear results and reset status/progress
            self.clear_results()
            self.progress.setMaximum(100)
            self.progress.setValue(0)
            self.status_label.setText("Ready")
        except Exception:
            pass

    def _ellipsize_middle_ascii(self, s: str, max_len: int) -> str:
        """Return an ASCII middle-ellipsized string using "..." when length exceeds max_len.
        Keeps head and tail segments; ensures total length <= max_len.
        """
        try:
            if not s or len(s) <= max_len or max_len <= 3:
                return s
            # Compute head/tail lengths
            rem = max_len - 3
            head = rem // 2
            tail = rem - head
            if head < 1:
                head = 1
            if tail < 1:
                tail = 1
            return s[:head] + "..." + s[-tail:]
        except Exception:
            return s

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
        # Refresh row styles after bulk toggle
        self._refresh_all_ioc_row_styles()

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
            # Determinate from the start: avoid busy animation chunk jumping
            self.progress.setMaximum(100)
            self.progress.setValue(0)
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
        self._worker = IoCScanWorker(
            self.bv,
            patterns,
            filter_live_domains=bool(getattr(self, "_resolvable_only", False)),
        )
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

    # ---------- UI styling helpers (accent color + IoC row visibility) ----------

    def _resolve_accent_color(self) -> QColor:
        """Try to use Binary Ninja's theme accent; fall back to Qt palette.
        Returns a QColor that should be clearly visible on the current background.
        """
        # Attempt to pull BN theme color via binaryninjaui if available
        try:
            from binaryninjaui import getThemeColor  # type: ignore
            from binaryninja.enums import ThemeColor  # type: ignore

            # Prefer a strong standard highlight; fall back to selection color
            qcol = getThemeColor(ThemeColor.BlueStandardHighlightColor)
            if isinstance(qcol, QColor):
                return qcol
            # Some builds might return a tuple; attempt conversion
            if (
                qcol
                and hasattr(qcol, "red")
                and hasattr(qcol, "green")
                and hasattr(qcol, "blue")
            ):
                return QColor(qcol.red(), qcol.green(), qcol.blue())
        except Exception:
            pass
        # Fallback to the widget palette highlight color
        try:
            return self.palette().highlight().color()
        except Exception:
            pass
        # Ultimate fallback: a safe blue accent
        return QColor(0x00, 0x78, 0xD7)

    def _accent_rgb(self) -> tuple:
        c = self._accent_qcolor
        return (c.red(), c.green(), c.blue())

    def _accent_css(self, alpha: int = 48) -> str:
        """Return rgba() string for accent with given alpha (0-255)."""
        r, g, b = self._accent_rgb()
        # Qt css uses rgba(r,g,b,a) with 0-255 alpha in many styles
        return f"rgba({r}, {g}, {b}, {alpha})"

    def _wire_ioc_row_styling(self, container: QWidget, cb: QCheckBox):
        """No-op: keep default theme appearance for checkboxes and rows."""
        try:
            cb.setStyleSheet("")
        except Exception:
            pass
        try:
            container.setStyleSheet("")
        except Exception:
            pass

    def _refresh_all_ioc_row_styles(self):
        for r in range(self.ioc_table.rowCount()):
            w = self.ioc_table.cellWidget(r, 0)
            if not w:
                continue
            cb = w.findChild(QCheckBox)
            if cb:
                # Ensure any prior custom style is cleared
                try:
                    cb.setStyleSheet("")
                    w.setStyleSheet("")
                except Exception:
                    pass

    def _apply_control_styles(self):
        """Style progress bar and search bar using Binary Ninja theme colors."""
        # Borders: use the same color as checkbox borders
        outline = self._checkbox_border_color()
        button_col = self._button_color()
        self._progress_chunk_color = button_col
        self._apply_progress_style(outline, button_col)

        # Search bar: force checkbox-border color in all interactive states
        # Use pane background from theme for a coherent fill
        try:
            pane_bg = (
                self._theme_color("ActivePaneBackgroundColor")
                or self._theme_color("InactivePaneBackgroundColor")
                or self.palette().base().color()
            )
        except Exception:
            pane_bg = self.palette().base().color()
        sel = outline
        le_css = (
            "QLineEdit {"
            f" background-color: {self._qcolor_css(pane_bg)}; border: 1px solid {self._qcolor_css(outline)}; border-radius: 0px;"
            " padding: 3px; color: palette(window-text);"
            "}"
            f" QLineEdit:focus {{ border: 1px solid {self._qcolor_css(sel)}; }}"
            f" QLineEdit:hover {{ border: 1px solid {self._qcolor_css(sel)}; }}"
            f" QLineEdit:disabled {{ border: 1px solid {self._qcolor_css(sel)}; color: palette(mid); }}"
            " QLineEdit::placeholder { color: palette(mid); }"
        )
        try:
            self.search_edit.setStyleSheet(le_css)
        except Exception:
            pass

    def _apply_progress_style(self, outline: QColor, button: QColor):
        """Apply progress bar style: border uses CommentColor; chunk uses button color; background uses pane/base color.
        This ensures the bar is not fully colored at 0% and fills progressively.
        """
        # Neutral background from theme pane/base color
        try:
            bg = (
                self._theme_color("ActivePaneBackgroundColor")
                or self._theme_color("InactivePaneBackgroundColor")
                or self.palette().base().color()
            )
        except Exception:
            bg = self.palette().base().color()
        bg_css = self._qcolor_css(bg)
        chunk_css = self._qcolor_css(button)
        pb_css = (
            "QProgressBar {"
            f" border: 1px solid {self._qcolor_css(outline)}; border-radius: 0px;"
            f" background-color: {bg_css}; color: palette(window-text); text-align: center;"
            "}"
            f" QProgressBar::chunk {{ background-color: {chunk_css}; border-radius: 0px; }}"
        )
        try:
            self.progress.setStyleSheet(pb_css)
        except Exception:
            pass

    def _set_progress_status(self, success: bool | None):
        """Keep border using CommentColor; chunk uses button color; background uses pane/base."""
        outline = self._theme_color("CommentColor")
        self._progress_chunk_color = self._button_color()
        self._apply_progress_style(outline, self._progress_chunk_color)

    def _button_color(self) -> QColor:
        """Return a color that matches the visual button color.
        Prefer the highlight/accent when Button role is too neutral (often equals border/base).
        """
        try:
            pal = (
                self.btn_scan.palette() if hasattr(self, "btn_scan") else self.palette()
            )
            col_btn = pal.color(QPalette.Button)
            col_hl = pal.highlight().color()
            # If Button color is too close to border/window (neutral), use highlight which better reflects real button
            try:
                border = self._theme_color("CommentColor")
                win = pal.window().color()
            except Exception:
                border = QColor(128, 128, 128)
                win = pal.window().color() if pal else QColor(40, 40, 40)

            def _dist(a: QColor, b: QColor) -> int:
                return (
                    abs(a.red() - b.red())
                    + abs(a.green() - b.green())
                    + abs(a.blue() - b.blue())
                )

            # If Button looks like border/window (very small distance), switch to highlight
            if _dist(col_btn, border) <= 12 or _dist(col_btn, win) <= 12:
                return col_hl
            return col_btn
        except Exception:
            # Fallback to a reasonable accent
            try:
                return self._theme_color("BlueStandardHighlightColor")
            except Exception:
                return QColor(0, 120, 215)

    def _apply_results_table_style(self):
        """Use Binary Ninja theme colors for grid/rows/selection/header in results table."""
        comment = self._theme_color("CommentColor")
        bg = self._theme_color("ActivePaneBackgroundColor") or self._theme_color(
            "InactivePaneBackgroundColor"
        )
        alt_bg = (
            self._theme_color("BackgroundHighlightLightColor")
            or self._theme_color("BackgroundHighlightDarkColor")
            or bg
        )
        sel = (
            self._theme_color("TokenSelectionColor")
            or self._theme_color("SelectionColor")
            or self._accent_qcolor
        )
        # Do not force a header background color; use theme default

        table_css = (
            "QTableView {"
            f" gridline-color: {self._qcolor_css(comment)};"
            f" border: 1px solid {self._qcolor_css(comment)};"
            f" border-radius: 0px;"
            f" background-color: {self._qcolor_css(bg)};"
            f" alternate-background-color: {self._qcolor_css(alt_bg)};"
            "}"
            " QTableView::item {"
            " border: none;"
            " padding: 2px 4px;"
            "}"
            f" QTableView::item:selected {{ background-color: {self._qcolor_css(sel)}; color: palette(bright-text); }}"
            " QHeaderView::section {"
            " border: none;"
            f" border-bottom: 1px solid {self._qcolor_css(comment)};"
            " padding: 4px 6px;"
            "}"
            " QHeaderView::section:horizontal {"
            f" border-right: 1px solid {self._qcolor_css(comment)};"
            "}"
            " QHeaderView::section:horizontal:last {"
            " border-right: none;"
            "}"
            " QTableCornerButton::section {"
            " border: none;"
            " background-color: transparent;"
            "}"
        )
        self.results_table.setStyleSheet(table_css)

    def _apply_ioc_table_style(self):
        """Make IoC types box look like a table: same border color, gridlines, and alternating rows."""
        comment = self._theme_color("CommentColor")
        bg = self._theme_color("ActivePaneBackgroundColor") or self._theme_color(
            "InactivePaneBackgroundColor"
        )
        alt_bg = (
            self._theme_color("BackgroundHighlightLightColor")
            or self._theme_color("BackgroundHighlightDarkColor")
            or bg
        )
        sel = (
            self._theme_color("TokenSelectionColor")
            or self._theme_color("SelectionColor")
            or self._accent_qcolor
        )
        box_css = (
            "QWidget#ioc_box {"
            f" border: 1px solid {self._qcolor_css(comment)};"
            f" border-radius: 0px;"
            f" background-color: {self._qcolor_css(bg)};"
            "}"
        )
        table_css = (
            "QTableView {"
            f" gridline-color: {self._qcolor_css(comment)};"
            f" border-radius: 0px;"
            f" background-color: {self._qcolor_css(bg)};"
            f" alternate-background-color: {self._qcolor_css(alt_bg)};"
            "}"
            " QTableView::item { border: none; padding: 2px 4px; }"
            f" QTableView::item:selected {{ background-color: {self._qcolor_css(sel)}; color: palette(bright-text); }}"
        )
        try:
            # Apply border/background to the box container
            self.ioc_box.setStyleSheet(box_css)
            # Apply grid/alt-row styling to the inner table to match right side
            self.ioc_table.setStyleSheet(table_css)
        except Exception:
            pass

    def _build_category_separator(
        self, total_height: int = 10, thickness: int = 1
    ) -> QWidget:
        """Create a separator row with a 1px rule centered vertically between categories.
        total_height controls the visual gap; thickness is the rule thickness.
        """
        try:
            color = self._theme_color("CommentColor")
        except Exception:
            color = QColor(128, 128, 128)
        container = QWidget()
        try:
            container.setFixedHeight(total_height)
            lay = QVBoxLayout(container)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(0)
            lay.addStretch(1)
            line = QWidget()
            line.setFixedHeight(thickness)
            line.setStyleSheet(f"background-color: {self._qcolor_css(color)};")
            lay.addWidget(line)
            lay.addStretch(1)
            container.setLayout(lay)
        except Exception:
            try:
                container.setFixedHeight(max(4, total_height))
            except Exception:
                pass
        return container

    def _category_divider_gap(self) -> int:
        """Return the vertical gap between a divider line and the next category title.
        Mirrors defaults from _build_category_separator(total_height=10, thickness=1).
        Computed as half of (total_height - thickness).
        """
        total_height = 10
        thickness = 1
        try:
            return max(0, int((total_height - thickness) // 2))
        except Exception:
            return 4

    def _corner_radius_px(self) -> int:
        """Unified corner radius in pixels for controls/boxes."""
        return 6

    def _theme_color(self, name: str) -> QColor:
        """Fetch a QColor from Binary Ninja theme by ThemeColor name. Safe fallback to palette."""
        try:
            from binaryninjaui import getThemeColor  # type: ignore
            from binaryninja.enums import ThemeColor  # type: ignore

            if hasattr(ThemeColor, name):
                return getThemeColor(getattr(ThemeColor, name))
        except Exception:
            pass
        # Palette-based fallback
        try:
            pal = self.palette()
            if name.endswith("BackgroundColor"):
                return pal.window().color()
            if name.endswith("SelectionColor"):
                return pal.highlight().color()
            # Outline fallback to mid color
            return pal.mid().color()
        except Exception:
            return self._accent_qcolor

    def _qcolor_css(self, c: QColor, alpha: int | None = None) -> str:
        """Return CSS rgba()/rgb() from QColor using optional alpha override (0-255)."""
        if c is None:
            c = self._accent_qcolor
        if alpha is None:
            return f"rgb({c.red()},{c.green()},{c.blue()})"
        return f"rgba({c.red()},{c.green()},{c.blue()},{alpha})"

    def _wrapable_text(self, s: str) -> str:
        """Return text with zero-width space opportunities so Qt can wrap long tokens.
        - Inserts U+200B after common separators (/, \\, ., :, ?, &, =, -, _)
        - Also inserts U+200B every self._wrap_run_length chars in long runs with no separators
        Original string is preserved for tooltips/export.
        """
        if not s:
            return s
        breaks = set("/\\.:?&=-_")
        out = []
        run = 0
        for ch in s:
            out.append(ch)
            if ch in breaks:
                out.append("")
                run = 0
            else:
                run += 1
                if self._wrap_run_length and run >= self._wrap_run_length:
                    out.append("")
                    run = 0
        return "".join(out)

    def _theme_color_if_available(self, name: str):
        """Return a QColor for a Binary Ninja ThemeColor if it exists; otherwise None.
        Does not fall back to palette. Safe to use for probing token availability.
        """
        try:
            from binaryninjaui import getThemeColor  # type: ignore
            from binaryninja.enums import ThemeColor  # type: ignore

            if hasattr(ThemeColor, name):
                return getThemeColor(getattr(ThemeColor, name))
        except Exception:
            pass
        return None

    def _text_color(self) -> QColor:
        """Return theme-driven text color.
       Prefer Binary Ninja theme token 'Text' (or 'TextColor') when available,
        otherwise fall back to the palette window text, then a safe light gray.
        """
        # Try explicit BN theme tokens first without palette fallback
        c = self._theme_color_if_available("Text")
        if isinstance(c, QColor):
            return c
        c = self._theme_color_if_available("TextColor")
        if isinstance(c, QColor):
            return c
        # Fall back to palette window text
        try:
            return self.palette().windowText().color()
        except Exception:
            pass
        # Last resort: try a reasonable token, else hardcoded
        c = self._theme_color_if_available("InstructionColor")
        if isinstance(c, QColor):
            return c
        return QColor(220, 220, 220)

    def _checkbox_border_color(self) -> QColor:
        """Return the color used for checkbox borders so search bar matches it."""
        try:
            return self._theme_color("CommentColor")
        except Exception:
            try:
                return self.palette().mid().color()
            except Exception:
                return QColor(120, 120, 120)

    def _apply_checkbox_border_style(self):
        """Ensure all IoC checkboxes use ProxyStyle (custom border + visible tick).
        Avoid Qt StyleSheet rules for QCheckBox::indicator because they override custom painting
        and can hide the check mark depending on theme.
        """
        try:
            border = self._theme_color("CommentColor")
            tick = self._text_color()
            for r in range(self.ioc_table.rowCount()):
                w = self.ioc_table.cellWidget(r, 0)
                if not w:
                    continue
                cb = w.findChild(QCheckBox)
                if not cb:
                    continue
                cb.setProperty("ioc_border_qcolor", border)
                cb.setProperty("ioc_tick_qcolor", tick)
                if self._checkbox_style is not None:
                    cb.setStyle(self._checkbox_style)
                # Clear any per-widget stylesheet that might interfere
                cb.setStyleSheet("")
        except Exception:
            pass

    def eventFilter(self, watched, event):
        """Toggle IoC checkbox when user clicks anywhere inside the cell widget.
        This keeps UX smooth even if indicator visuals vary by theme/CSS.
        """
        try:
            # Show forbidden cursor when hovering disabled buttons; do not alter button style
            from PySide6.QtWidgets import QPushButton

            if isinstance(watched, QPushButton):
                if event.type() in (QEvent.Enter, QEvent.HoverEnter, QEvent.HoverMove):
                    if not watched.isEnabled():
                        watched.setCursor(Qt.ForbiddenCursor)
                    else:
                        watched.unsetCursor()
                elif event.type() in (QEvent.Leave, QEvent.HoverLeave, QEvent.Hide):
                    watched.unsetCursor()
                # Never consume button events here
                return False
            if isinstance(watched, QWidget) and watched.property("ioc_cb") is not None:
                # If the click is on the actual checkbox (or its children), let it handle itself
                if event.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease):
                    cb = watched.property("ioc_cb")
                    if isinstance(cb, QCheckBox):
                        child = watched.childAt(event.pos())
                        if child is not None and (
                            child is cb or cb.isAncestorOf(child)
                        ):
                            return False  # do not double-toggle
                    if (
                        event.type() == QEvent.MouseButtonRelease
                        and event.button() == Qt.LeftButton
                    ):
                        if isinstance(cb, QCheckBox) and cb.isEnabled():
                            cb.setChecked(not cb.isChecked())
                            return True
        except Exception:
            pass
        return super().eventFilter(watched, event)

    def _install_button_event_filters(self):
        """Install event filters so disabled buttons show a 'not-allowed' cursor on hover.
        No visual style is changed; only the cursor feedback is provided.
        """
        buttons = [
            getattr(self, "btn_scan", None),
            getattr(self, "btn_cancel", None),
            getattr(self, "btn_clear", None),
            getattr(self, "btn_export", None),
            getattr(self, "btn_select_all", None),
            getattr(self, "btn_select_none", None),
        ]
        for b in buttons:
            if b is not None:
                try:
                    b.setAttribute(Qt.WA_Hover, True)
                except Exception:
                    pass
                try:
                    b.installEventFilter(self)
                except Exception:
                    pass

    def _apply_cancel_disabled_style(self):
        """Make only the Cancel button's disabled state use the normal (enabled) background color.
        Does not alter other buttons or other states.
        """
        try:
            # Use an enabled button's color as the reference (Scan is enabled when idle)
            ref_pal = (
                self.btn_scan.palette() if hasattr(self, "btn_scan") else self.palette()
            )
            btn_col = ref_pal.color(QPalette.Button)
            rgb = self._qcolor_css(btn_col)
            css = (
                "QPushButton#btn_cancel:disabled {"
                f" background-color: {rgb};"
                f" color: {self._qcolor_css(self._text_color())};"
                "}"
            )
            self.btn_cancel.setStyleSheet(css)
        except Exception:
            pass

    def _apply_export_disabled_style(self):
        """Make only the Export button's disabled state use the normal (enabled) background color.
        Does not alter other buttons or other states.
        """
        try:
            ref_pal = (
                self.btn_scan.palette() if hasattr(self, "btn_scan") else self.palette()
            )
            btn_col = ref_pal.color(QPalette.Button)
            rgb = self._qcolor_css(btn_col)
            css = (
                "QPushButton#btn_export:disabled {"
                f" background-color: {rgb};"
                f" color: {self._qcolor_css(self._text_color())};"
                "}"
            )
            self.btn_export.setStyleSheet(css)
        except Exception:
            pass

    def _apply_button_text_style(self):
        """Apply text color for all buttons using the theme 'Text' token when available."""
        try:
            text_css = self._qcolor_css(self._text_color())
            css = f"QPushButton {{ color: {text_css}; }}"
            buttons = [
                getattr(self, "btn_scan", None),
                getattr(self, "btn_cancel", None),
                getattr(self, "btn_clear", None),
                getattr(self, "btn_export", None),
                getattr(self, "btn_select_all", None),
                getattr(self, "btn_select_none", None),
            ]
            for b in buttons:
                if b is not None:
                    existing = b.styleSheet() or ""
                    combined = (existing + "\n" + css).strip() if existing else css
                    b.setStyleSheet(combined)
        except Exception:
            pass

    def _upsert_row(self, ioc_type: str, value: str, addr_str: str):
        # Update row if Type+Value exists; else insert a new row.
        # For display, replace underscores with spaces in type column
        ioc_type_disp = (
            self._type_display.get(ioc_type, ioc_type.replace("_", " "))
            if ioc_type
            else ioc_type
        )
        rows = self.results_table.rowCount()
        target_row = -1
        for r in range(rows):
            t_item = self.results_table.item(r, 0)
            v_item = self.results_table.item(r, 1)
            if (
                t_item
                and v_item
                and t_item.text() == ioc_type_disp
                and v_item.text().replace("", "") == value
            ):
                target_row = r
                break
        if target_row == -1:
            target_row = rows
            self.results_table.insertRow(target_row)
            self.results_table.setItem(target_row, 0, QTableWidgetItem(ioc_type_disp))
            val_item = QTableWidgetItem(self._wrapable_text(value))
            val_item.setToolTip(value)
            self.results_table.setItem(target_row, 1, val_item)
        else:
            # Update existing value text with wrap opportunities too
            val_item = QTableWidgetItem(self._wrapable_text(value))
            val_item.setToolTip(value)
            self.results_table.setItem(target_row, 1, val_item)
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
                    (type_item.text() if type_item else "").replace("", ""),
                    (value_item.text() if value_item else "").replace("", ""),
                    (addr_item.text() if addr_item else "").replace("", ""),
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
            # Ensure left title row and controls are never clipped
            # Use computed content width without over-aggressive clamping
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
        # Use green highlight color for success
        try:
            self._set_progress_status(True)
        except Exception:
            pass
        self.status_label.setText(
            f"Findings: {len(results)} | Strings Scanned: {scanned} | Elapsed {elapsed:.1f}s"
        )
        self._set_scanning(False)
        self._teardown_thread()

    def _on_failed(self, msg: str):
        self.status_label.setText(f"Scan failed: {msg}")
        self._set_scanning(False)
        # Use red highlight color for failure
        try:
            self._set_progress_status(False)
        except Exception:
            pass
        self._teardown_thread()

    def _on_canceled(self):
        self.status_label.setText("Scan canceled")
        self._set_scanning(False)
        # Reset progress bar to 0%
        try:
            self.progress.setMaximum(100)
            self.progress.setValue(0)
        except Exception:
            pass
        # Restore default selection-themed chunk color
        try:
            self._set_progress_status(None)
        except Exception:
            pass
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
        # Keep columns stretched to available width so horizontal scrollbars are unnecessary
        try:
            header = self.results_table.horizontalHeader()
            for c in range(self.results_table.columnCount()):
                header.setSectionResizeMode(c, QHeaderView.Stretch)
        except Exception:
            pass
        self._columns_sized = True

    def _on_results_item_clicked(self, item: QTableWidgetItem):
        try:
            col = item.column()
            row = item.row()
            if col == 1:
                # Copy Value text (strip zero-width spaces) to clipboard
                txt = item.text().replace("", "") if item else ""
                from PySide6.QtWidgets import QApplication

                QApplication.instance().clipboard().setText(txt)
                try:
                    self.status_label.setText("Copied value to clipboard")
                except Exception:
                    pass
            elif col == 2:
                # Jump to address (handles single or multiple)
                self.goto_address_from_item(item)
        except Exception:
            pass

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
