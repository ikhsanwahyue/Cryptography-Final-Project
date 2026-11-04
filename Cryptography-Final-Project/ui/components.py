"""
Forensic Tactical HUD Components for LexVault CustomTkinter GUI.
Implements the strict color palette:
- Base: #0B0F19
- Surface Card: #161F30
- Border: #24334D
- Primary Cobalt: #2563EB
- Verified Emerald: #10B981
- Alert Hazard: #F59E0B / #EF4444
- Monospace Font: Consolas / Courier New
"""

import platform
from datetime import datetime
from typing import Any, Optional, Tuple

import customtkinter as ctk

# ============================================================================
# COLOR PALETTE & TYPOGRAPHY CONSTANTS
# ============================================================================
COLOR_BASE = "#0B0F19"
COLOR_SURFACE = "#161F30"
COLOR_SURFACE_DARK = "#0F1624"
COLOR_BORDER = "#24334D"
COLOR_PRIMARY = "#2563EB"
COLOR_PRIMARY_HOVER = "#1D4ED8"
COLOR_EMERALD = "#10B981"
COLOR_EMERALD_DARK = "#065F46"
COLOR_AMBER = "#F59E0B"
COLOR_CRIMSON = "#EF4444"
COLOR_CRIMSON_DARK = "#7F1D1D"
COLOR_TEXT_PRIMARY = "#F8FAFC"
COLOR_TEXT_MUTED = "#94A3B8"

MONO_FAMILY = "Consolas" if platform.system().lower() == "windows" else "Courier New"


def get_mono_font(size: int = 13, weight: str = "normal") -> Tuple[str, int, str]:
    return (MONO_FAMILY, size, weight)


class HUDCard(ctk.CTkFrame):
    """
    Tactical Forensic Surface Card with #161F30 background and #24334D border.
    """

    def __init__(
        self,
        master: Any,
        title: Optional[str] = None,
        subtitle: Optional[str] = None,
        border_color: str = COLOR_BORDER,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            fg_color=COLOR_SURFACE,
            border_color=border_color,
            border_width=1,
            corner_radius=8,
            **kwargs,
        )
        self.header_frame: Optional[ctk.CTkFrame] = None
        if title:
            self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
            self.header_frame.pack(fill="x", padx=14, pady=(12, 6))

            title_lbl = ctk.CTkLabel(
                self.header_frame,
                text=title.upper(),
                font=get_mono_font(13, "bold"),
                text_color=COLOR_TEXT_PRIMARY,
                anchor="w",
            )
            title_lbl.pack(side="left", fill="x")

            if subtitle:
                sub_lbl = ctk.CTkLabel(
                    self.header_frame,
                    text=subtitle,
                    font=get_mono_font(11, "normal"),
                    text_color=COLOR_TEXT_MUTED,
                    anchor="e",
                )
                sub_lbl.pack(side="right")


class StatusBadge(ctk.CTkLabel):
    """
    Compact tactical status badge supporting VERIFIED, WARNING, DANGER, and INFO states.
    """

    def __init__(
        self,
        master: Any,
        text: str = "STANDBY",
        status: str = "INFO",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            text=f" {text} ",
            font=get_mono_font(11, "bold"),
            corner_radius=4,
            padx=8,
            pady=3,
            **kwargs,
        )
        self.set_status(text, status)

    def set_status(self, text: str, status: str = "INFO") -> None:
        level = status.upper()
        if level in ("SUCCESS", "VERIFIED", "UNLOCKED", "ACTIVE"):
            fg = "#064E3B"
            tc = COLOR_EMERALD
        elif level in ("WARN", "WARNING", "PENDING"):
            fg = "#451A03"
            tc = COLOR_AMBER
        elif level in ("ERROR", "CRITICAL", "BREACH", "LOCKED", "DANGER"):
            fg = "#450A0A"
            tc = COLOR_CRIMSON
        else:
            fg = "#1E3A8A"
            tc = "#93C5FD"

        self.configure(text=f" ● {text} ", fg_color=fg, text_color=tc)


class ForensicLogViewer(ctk.CTkFrame):
    """
    Real-Time Forensic Custody Event Logger terminal widget.
    """

    def __init__(self, master: Any, height: int = 125, **kwargs: Any) -> None:
        super().__init__(
            master,
            fg_color=COLOR_SURFACE_DARK,
            border_color=COLOR_BORDER,
            border_width=1,
            corner_radius=6,
            **kwargs,
        )

        top_bar = ctk.CTkFrame(self, fg_color="transparent")
        top_bar.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            top_bar,
            text="▸ REAL-TIME FORENSIC TELEMETRY & AUDIT LOG (ISO/IEC 27037)",
            font=get_mono_font(11, "bold"),
            text_color=COLOR_TEXT_MUTED,
        ).pack(side="left")

        clear_btn = ctk.CTkButton(
            top_bar,
            text="CLEAR LOG",
            width=80,
            height=20,
            font=get_mono_font(10, "bold"),
            fg_color=COLOR_SURFACE,
            hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_MUTED,
            command=self.clear,
        )
        clear_btn.pack(side="right")

        self.textbox = ctk.CTkTextbox(
            self,
            height=height,
            fg_color=COLOR_BASE,
            text_color=COLOR_TEXT_PRIMARY,
            border_color=COLOR_BORDER,
            border_width=1,
            font=get_mono_font(11, "normal"),
            wrap="word",
        )
        self.textbox.pack(fill="both", expand=True, padx=10, pady=(2, 8))
        self.textbox.configure(state="disabled")

    def log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        tag = level.upper()
        prefix_map = {
            "INFO": "[INFO]",
            "SUCCESS": "[OK-VERIFIED]",
            "WARN": "[WARNING]",
            "ERROR": "[ERROR]",
            "CRITICAL": "[KILL-SWITCH]",
        }
        prefix = prefix_map.get(tag, f"[{tag}]")
        line = f"{timestamp} {prefix} {message}\n"

        self.textbox.configure(state="normal")
        self.textbox.insert("end", line)
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def clear(self) -> None:
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.configure(state="disabled")

