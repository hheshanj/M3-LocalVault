import os
import cv2
import time
import json
import string
import random
import threading
import io
import atexit
import shutil
from pathlib import Path
from datetime import datetime
from deepface import DeepFace
from cryptography.fernet import Fernet
import customtkinter as ctk
from tkinter import filedialog
from PIL import Image

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & ENVIRONMENT
# ══════════════════════════════════════════════════════════════════════════════
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

APP_NAME = "M3-VAULT"
VAULT_DIR = Path("vault_storage")
INTRUDER_DIR = Path("intruders")
TEMP_DIR = Path(".vault_temp")
KEY_FILE = "master.key"
MASTER_FACE = "master_face.jpg"
PASSWORDS_DB = "passwords.vault"

# Create directories
for directory in [VAULT_DIR, INTRUDER_DIR, TEMP_DIR]:
    directory.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# MATERIAL YOU (M3) DESIGN SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
class M3:
    """Material You Design Tokens - Dark Theme"""
    
    # Background & Surface
    BG = "#0D1117"
    BG_ELEVATED = "#161B22"
    SURFACE = "#1C2128"
    SURFACE_VARIANT = "#252C35"
    SURFACE_CONTAINER = "#21262D"
    SURFACE_CONTAINER_HIGH = "#2D333B"
    SURFACE_BRIGHT = "#373E47"
    
    # Primary Palette (Cyan/Sky)
    PRIMARY = "#58A6FF"
    PRIMARY_VARIANT = "#79C0FF"
    PRIMARY_CONTAINER = "#0D419D"
    ON_PRIMARY = "#002D6D"
    ON_PRIMARY_CONTAINER = "#D6E3FF"
    
    # Secondary Palette (Purple)
    SECONDARY = "#BC8CFF"
    SECONDARY_CONTAINER = "#4A2F82"
    ON_SECONDARY = "#2D0A5E"
    
    # Tertiary Palette (Pink)
    TERTIARY = "#FF7EB3"
    TERTIARY_CONTAINER = "#6D2B49"
    
    # Error/Danger
    ERROR = "#FF6B6B"
    ERROR_CONTAINER = "#5C1E1E"
    ON_ERROR = "#3D0000"
    
    # Success
    SUCCESS = "#56D364"
    SUCCESS_CONTAINER = "#1B4D28"
    ON_SUCCESS = "#0A2912"
    
    # Warning
    WARNING = "#F0B429"
    WARNING_CONTAINER = "#533D10"
    
    # Text & Content
    TEXT_PRIMARY = "#F0F6FC"
    TEXT_SECONDARY = "#8B949E"
    TEXT_TERTIARY = "#6E7681"
    TEXT_DISABLED = "#484F58"
    
    # Outline & Borders
    OUTLINE = "#30363D"
    OUTLINE_VARIANT = "#21262D"
    DIVIDER = "#21262D"
    
    # Typography - Using system fonts with fallbacks
    FONT_DISPLAY = ("SF Pro Display", "Segoe UI", "Helvetica Neue", "Arial")
    FONT_BODY = ("SF Pro Text", "Segoe UI", "Helvetica Neue", "Arial")
    FONT_MONO = ("SF Mono", "Cascadia Code", "Consolas", "monospace")
    
    # Sizing
    RADIUS_SMALL = 8
    RADIUS_MEDIUM = 12
    RADIUS_LARGE = 16
    RADIUS_XLARGE = 24
    RADIUS_FULL = 9999


# ══════════════════════════════════════════════════════════════════════════════
# ENCRYPTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class CryptoEngine:
    """Handles all encryption/decryption operations"""
    
    def __init__(self, key_file: str):
        self.key_file = key_file
        self.cipher = self._initialize_cipher()
    
    def _initialize_cipher(self) -> Fernet:
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
        else:
            with open(self.key_file, "rb") as f:
                key = f.read()
        return Fernet(key)
    
    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)
    
    def encrypt_file(self, source: str, dest: str) -> None:
        with open(source, "rb") as f:
            data = f.read()
        with open(dest, "wb") as f:
            f.write(self.encrypt(data))
    
    def decrypt_file(self, source: str, dest: str) -> None:
        with open(source, "rb") as f:
            data = f.read()
        with open(dest, "wb") as f:
            f.write(self.decrypt(data))


# Initialize crypto engine
crypto = CryptoEngine(KEY_FILE)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════
def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """Generate a cryptographically secure password"""
    characters = string.ascii_letters + string.digits
    if use_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(random.SystemRandom().choice(characters) for _ in range(length))


def secure_delete(path: Path, passes: int = 3) -> None:
    """Securely delete a file by overwriting with random data"""
    if not path.exists():
        return
    
    size = path.stat().st_size
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    path.unlink()


def format_file_size(size: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def format_timestamp(ts: float) -> str:
    """Format Unix timestamp to readable string"""
    return datetime.fromtimestamp(ts).strftime("%b %d, %Y at %I:%M %p")


def cleanup_temp_directory() -> None:
    """Clean up temporary files on exit"""
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
        TEMP_DIR.mkdir(exist_ok=True)


atexit.register(cleanup_temp_directory)


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM WIDGETS
# ══════════════════════════════════════════════════════════════════════════════
class Toast(ctk.CTkFrame):
    """Material-style toast notification with auto-dismiss"""
    
    def __init__(self, parent, message: str, toast_type: str = "info", duration: int = 3500):
        super().__init__(parent, corner_radius=M3.RADIUS_MEDIUM)
        
        # Color mapping
        color_map = {
            "info": (M3.PRIMARY_CONTAINER, M3.PRIMARY, "ℹ"),
            "success": (M3.SUCCESS_CONTAINER, M3.SUCCESS, "✓"),
            "error": (M3.ERROR_CONTAINER, M3.ERROR, "✕"),
            "warning": (M3.WARNING_CONTAINER, M3.WARNING, "⚠")
        }
        
        bg_color, text_color, icon = color_map.get(toast_type, color_map["info"])
        
        self.configure(fg_color=bg_color, border_width=1, border_color=text_color)
        
        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(padx=16, pady=10)
        
        ctk.CTkLabel(
            content,
            text=f"{icon}   {message}",
            font=(M3.FONT_BODY[0], 13, "bold"),
            text_color=text_color
        ).pack()
        
        # Position and animate
        self.place(relx=0.5, rely=0.92, anchor="center")
        self.lift()
        
        # Auto dismiss
        self.after(duration, self._fade_out)
    
    def _fade_out(self):
        self.destroy()


class ModernEntry(ctk.CTkEntry):
    """Styled entry widget with focus effects"""
    
    def __init__(self, master, **kwargs):
        default_config = {
            "height": 48,
            "corner_radius": M3.RADIUS_MEDIUM,
            "fg_color": M3.SURFACE_VARIANT,
            "border_width": 2,
            "border_color": M3.OUTLINE,
            "text_color": M3.TEXT_PRIMARY,
            "placeholder_text_color": M3.TEXT_TERTIARY,
            "font": (M3.FONT_BODY[0], 14)
        }
        default_config.update(kwargs)
        super().__init__(master, **default_config)
        
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)
    
    def _on_focus_in(self, event):
        self.configure(border_color=M3.PRIMARY)
    
    def _on_focus_out(self, event):
        self.configure(border_color=M3.OUTLINE)


class IconButton(ctk.CTkButton):
    """Circular icon button with hover effects"""
    
    def __init__(self, master, icon: str, size: int = 44, **kwargs):
        default_config = {
            "text": icon,
            "width": size,
            "height": size,
            "corner_radius": size // 2,
            "fg_color": "transparent",
            "hover_color": M3.SURFACE_VARIANT,
            "font": (M3.FONT_BODY[0], size // 2)
        }
        default_config.update(kwargs)
        super().__init__(master, **default_config)


class FileCard(ctk.CTkFrame):
    """Modern file card with metadata and actions"""
    
    FILE_ICONS = {
        'image': ('🖼️', ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg']),
        'document': ('📄', ['.txt', '.pdf', '.doc', '.docx', '.rtf']),
        'code': ('💻', ['.py', '.js', '.html', '.css', '.json', '.xml', '.md']),
        'video': ('🎬', ['.mp4', '.mov', '.avi', '.mkv', '.webm']),
        'audio': ('🎵', ['.mp3', '.wav', '.flac', '.aac', '.ogg']),
        'archive': ('📦', ['.zip', '.rar', '.7z', '.tar', '.gz']),
        'default': ('📎', [])
    }
    
    def __init__(self, master, file_path: Path, on_preview, on_open, on_delete, **kwargs):
        super().__init__(master, fg_color=M3.SURFACE, corner_radius=M3.RADIUS_LARGE, **kwargs)
        
        self.file_path = file_path
        self.default_bg = M3.SURFACE
        self.hover_bg = M3.SURFACE_CONTAINER_HIGH
        
        # Get file info
        ext = file_path.suffix.lower()
        icon = self._get_file_icon(ext)
        size = format_file_size(file_path.stat().st_size)
        modified = format_timestamp(file_path.stat().st_mtime)
        
        # Main container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=16, pady=14)
        
        # Left section - Icon and info
        left_section = ctk.CTkFrame(container, fg_color="transparent")
        left_section.pack(side="left", fill="x", expand=True)
        
        # Icon container
        icon_frame = ctk.CTkFrame(
            left_section, width=48, height=48,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.SURFACE_VARIANT
        )
        icon_frame.pack(side="left", padx=(0, 14))
        icon_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            icon_frame, text=icon,
            font=(M3.FONT_BODY[0], 22)
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # File info
        info_frame = ctk.CTkFrame(left_section, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(
            info_frame,
            text=file_path.name,
            font=(M3.FONT_BODY[0], 14, "bold"),
            text_color=M3.TEXT_PRIMARY,
            anchor="w"
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            info_frame,
            text=f"{size}  •  {ext.upper()[1:] if ext else 'FILE'}",
            font=(M3.FONT_BODY[0], 12),
            text_color=M3.TEXT_TERTIARY,
            anchor="w"
        ).pack(anchor="w")
        
        # Right section - Actions
        actions = ctk.CTkFrame(container, fg_color="transparent")
        actions.pack(side="right")
        
        # Preview button
        ctk.CTkButton(
            actions, text="Preview", width=80, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 12),
            command=lambda: on_preview(file_path)
        ).pack(side="left", padx=4)
        
        # Open button
        ctk.CTkButton(
            actions, text="Open", width=70, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 12, "bold"),
            command=lambda: on_open(file_path)
        ).pack(side="left", padx=4)
        
        # Delete button
        ctk.CTkButton(
            actions, text="🗑", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 14),
            command=lambda: on_delete(file_path)
        ).pack(side="left", padx=4)
        
        # Hover bindings
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        container.bind("<Enter>", self._on_enter)
        container.bind("<Leave>", self._on_leave)
    
    def _get_file_icon(self, ext: str) -> str:
        for icon, (emoji, extensions) in self.FILE_ICONS.items():
            if ext in extensions:
                return emoji
        return self.FILE_ICONS['default'][0]
    
    def _on_enter(self, event):
        self.configure(fg_color=self.hover_bg)
    
    def _on_leave(self, event):
        self.configure(fg_color=self.default_bg)


class PasswordCard(ctk.CTkFrame):
    """Password entry card with reveal, copy, and delete functionality"""
    
    def __init__(self, master, service: str, password: str, on_copy, on_delete, **kwargs):
        super().__init__(master, fg_color=M3.SURFACE, corner_radius=M3.RADIUS_MEDIUM, **kwargs)
        
        self.password = password
        self.is_revealed = False
        
        # Container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=16, pady=12)
        
        # Left - Service info
        left = ctk.CTkFrame(container, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        
        # Service icon and name
        header = ctk.CTkFrame(left, fg_color="transparent")
        header.pack(anchor="w")
        
        ctk.CTkLabel(
            header,
            text=f"🌐  {service}",
            font=(M3.FONT_BODY[0], 14, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        # Password display
        self.password_label = ctk.CTkLabel(
            left,
            text="•" * min(len(password), 20),
            font=(M3.FONT_MONO[0], 13),
            text_color=M3.TEXT_SECONDARY,
            anchor="w"
        )
        self.password_label.pack(anchor="w", pady=(4, 0))
        
        # Right - Actions
        actions = ctk.CTkFrame(container, fg_color="transparent")
        actions.pack(side="right")
        
        # Reveal button
        self.reveal_btn = ctk.CTkButton(
            actions, text="👁", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            font=(M3.FONT_BODY[0], 14),
            command=self._toggle_reveal
        )
        self.reveal_btn.pack(side="left", padx=3)
        
        # Copy button
        ctk.CTkButton(
            actions, text="Copy", width=65, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 12, "bold"),
            command=lambda: on_copy(password)
        ).pack(side="left", padx=3)
        
        # Delete button
        ctk.CTkButton(
            actions, text="🗑", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 14),
            command=lambda: on_delete(service)
        ).pack(side="left", padx=3)
        
        # Hover effect
        self.bind("<Enter>", lambda e: self.configure(fg_color=M3.SURFACE_CONTAINER_HIGH))
        self.bind("<Leave>", lambda e: self.configure(fg_color=M3.SURFACE))
    
    def _toggle_reveal(self):
        self.is_revealed = not self.is_revealed
        if self.is_revealed:
            self.password_label.configure(text=self.password)
            self.reveal_btn.configure(text="🙈")
        else:
            self.password_label.configure(text="•" * min(len(self.password), 20))
            self.reveal_btn.configure(text="👁")


class IntruderCard(ctk.CTkFrame):
    """Card displaying intruder attempt information"""
    
    def __init__(self, master, file_path: Path, on_view, on_delete, **kwargs):
        super().__init__(master, fg_color=M3.SURFACE, corner_radius=M3.RADIUS_MEDIUM, **kwargs)
        
        # Extract timestamp
        try:
            ts = int(file_path.stem.split('_')[1])
            time_str = format_timestamp(ts)
        except:
            time_str = "Unknown time"
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=16, pady=12)
        
        # Left - Alert icon and info
        left = ctk.CTkFrame(container, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        
        # Alert icon
        icon_frame = ctk.CTkFrame(
            left, width=42, height=42,
            corner_radius=21,
            fg_color=M3.ERROR_CONTAINER
        )
        icon_frame.pack(side="left", padx=(0, 12))
        icon_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            icon_frame, text="🚨",
            font=(M3.FONT_BODY[0], 18)
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # Info
        info = ctk.CTkFrame(left, fg_color="transparent")
        info.pack(side="left")
        
        ctk.CTkLabel(
            info,
            text="Unauthorized Access Attempt",
            font=(M3.FONT_BODY[0], 14, "bold"),
            text_color=M3.ERROR
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            info,
            text=time_str,
            font=(M3.FONT_BODY[0], 12),
            text_color=M3.TEXT_TERTIARY
        ).pack(anchor="w")
        
        # Right - Actions
        actions = ctk.CTkFrame(container, fg_color="transparent")
        actions.pack(side="right")
        
        ctk.CTkButton(
            actions, text="View Photo", width=100, height=34,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 12),
            command=lambda: on_view(file_path)
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            actions, text="🗑", width=34, height=34,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            command=lambda: on_delete(file_path)
        ).pack(side="left", padx=4)


class ConfirmDialog(ctk.CTkToplevel):
    """Custom confirmation dialog"""
    
    def __init__(self, parent, title: str, message: str, on_confirm, danger: bool = False):
        super().__init__(parent)
        
        self.title("")
        self.geometry("420x200")
        self.configure(fg_color=M3.BG_ELEVATED)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        # Center on parent
        self.update()
        x = parent.winfo_x() + (parent.winfo_width() - 420) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 200) // 2
        self.geometry(f"+{x}+{y}")
        
        # Content
        ctk.CTkLabel(
            self, text=title,
            font=(M3.FONT_DISPLAY[0], 20, "bold"),
            text_color=M3.ERROR if danger else M3.TEXT_PRIMARY
        ).pack(pady=(30, 10))
        
        ctk.CTkLabel(
            self, text=message,
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY,
            wraplength=350
        ).pack(pady=(0, 25))
        
        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        ctk.CTkButton(
            btn_frame, text="Cancel", width=100, height=40,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 14),
            command=self.destroy
        ).pack(side="left", padx=8)
        
        ctk.CTkButton(
            btn_frame, text="Confirm", width=100, height=40,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.ERROR if danger else M3.PRIMARY,
            hover_color=M3.ERROR_CONTAINER if danger else M3.PRIMARY_VARIANT,
            text_color="#FFFFFF",
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=lambda: [on_confirm(), self.destroy()]
        ).pack(side="left", padx=8)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class VaultApp(ctk.CTk):
    """Main M3-VAULT Application"""
    
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title(APP_NAME)
        self.geometry("1350x850")
        self.configure(fg_color=M3.BG)
        self.minsize(1100, 700)
        
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # State
        self.is_unlocked = False
        self.current_tab = "files"
        self.last_activity = time.time()
        
        # Show login screen
        self.show_login()
        
        # Start inactivity checker
        self._check_inactivity()
    
    def _check_inactivity(self):
        """Auto-lock after 5 minutes of inactivity"""
        if self.is_unlocked and (time.time() - self.last_activity) > 300:
            self.lock_vault()
        self.after(30000, self._check_inactivity)
    
    def _reset_activity(self, event=None):
        self.last_activity = time.time()
    
    def _clear_ui(self):
        for widget in self.winfo_children():
            widget.destroy()
    
    def show_toast(self, message: str, toast_type: str = "info"):
        Toast(self, message, toast_type)
    
    # ──────────────────────────────────────────────────────────────────────────
    # LOGIN SCREEN
    # ──────────────────────────────────────────────────────────────────────────
    def show_login(self):
        self._clear_ui()
        self.is_unlocked = False
        
        # Background pattern (subtle grid)
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo container
        logo_container = ctk.CTkFrame(
            bg_frame, width=130, height=130,
            corner_radius=65,
            fg_color=M3.PRIMARY_CONTAINER,
            border_width=3,
            border_color=M3.PRIMARY
        )
        logo_container.pack(pady=(0, 35))
        logo_container.pack_propagate(False)
        
        ctk.CTkLabel(
            logo_container, text="🔐",
            font=(M3.FONT_DISPLAY[0], 52)
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # App name
        ctk.CTkLabel(
            bg_frame, text=APP_NAME,
            font=(M3.FONT_DISPLAY[0], 48, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(pady=(0, 8))
        
        # Tagline
        ctk.CTkLabel(
            bg_frame, text="Secure • Private • Protected",
            font=(M3.FONT_BODY[0], 16),
            text_color=M3.TEXT_TERTIARY
        ).pack(pady=(0, 45))
        
        # Auth button
        self.auth_btn = ctk.CTkButton(
            bg_frame,
            text="    Unlock with Face ID    ",
            width=300, height=60,
            corner_radius=30,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 17, "bold"),
            command=self._start_auth_thread
        )
        self.auth_btn.pack(pady=12)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            bg_frame, text="",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_SECONDARY
        )
        self.status_label.pack(pady=18)
        
        # Setup face option (if not configured)
        if not os.path.exists(MASTER_FACE):
            setup_frame = ctk.CTkFrame(bg_frame, fg_color="transparent")
            setup_frame.pack(pady=15)
            
            ctk.CTkLabel(
                setup_frame,
                text="First time? ",
                font=(M3.FONT_BODY[0], 13),
                text_color=M3.TEXT_TERTIARY
            ).pack(side="left")
            
            setup_btn = ctk.CTkButton(
                setup_frame,
                text="Register Face ID",
                fg_color="transparent",
                hover_color=M3.SURFACE_VARIANT,
                text_color=M3.PRIMARY,
                font=(M3.FONT_BODY[0], 13, "bold"),
                command=self._setup_master_face
            )
            setup_btn.pack(side="left")
    
    def _setup_master_face(self):
        self.status_label.configure(text="📸 Capturing your face... Look at the camera")
        
        def capture():
            cap = cv2.VideoCapture(0)
            time.sleep(0.5)  # Allow camera to warm up
            ret, frame = cap.read()
            cap.release()
            
            if ret:
                cv2.imwrite(MASTER_FACE, frame)
                self.after(0, lambda: self.status_label.configure(
                    text="✓ Face ID registered successfully!",
                    text_color=M3.SUCCESS
                ))
                self.after(0, lambda: self.show_toast("Face ID registered!", "success"))
            else:
                self.after(0, lambda: self.status_label.configure(
                    text="✕ Camera error. Please try again.",
                    text_color=M3.ERROR
                ))
        
        threading.Thread(target=capture, daemon=True).start()
    
    def _start_auth_thread(self):
        if not os.path.exists(MASTER_FACE):
            self.show_toast("Please register Face ID first", "warning")
            return
        
        self.auth_btn.configure(state="disabled", text="   🔄  Scanning...   ")
        self.status_label.configure(text="Look at the camera", text_color=M3.TEXT_SECONDARY)
        threading.Thread(target=self._run_authentication, daemon=True).start()
    
    def _run_authentication(self):
        cap = cv2.VideoCapture(0)
        time.sleep(0.3)
        ret, frame = cap.read()
        cap.release()
        
        if not ret:
            self.after(0, lambda: self.show_toast("Camera not available", "error"))
            self.after(0, self._reset_auth_button)
            return
        
        temp_img = TEMP_DIR / "auth_capture.jpg"
        cv2.imwrite(str(temp_img), frame)
        
        try:
            result = DeepFace.verify(
                str(temp_img), MASTER_FACE,
                enforce_detection=True,
                detector_backend='opencv',
                model_name='VGG-Face'
            )
            
            if result['verified']:
                self.is_unlocked = True
                self.after(0, self.show_dashboard)
                self.after(0, lambda: self.show_toast("Welcome back!", "success"))
            else:
                # Log intruder
                intruder_file = INTRUDER_DIR / f"intruder_{int(time.time())}.jpg"
                shutil.copy(temp_img, intruder_file)
                self.after(0, lambda: self.show_toast("Access Denied • Intruder logged", "error"))
                self.after(0, self._reset_auth_button)
                
        except Exception as e:
            error_msg = str(e)
            if "Face" in error_msg or "detect" in error_msg.lower():
                self.after(0, lambda: self.show_toast("No face detected • Ensure good lighting", "warning"))
            else:
                self.after(0, lambda: self.show_toast(f"Auth error: {error_msg[:50]}", "error"))
            self.after(0, self._reset_auth_button)
        finally:
            if temp_img.exists():
                temp_img.unlink()
    
    def _reset_auth_button(self):
        self.auth_btn.configure(state="normal", text="    Unlock with Face ID    ")
        self.status_label.configure(text="")
    
    # ──────────────────────────────────────────────────────────────────────────
    # DASHBOARD
    # ──────────────────────────────────────────────────────────────────────────
    def show_dashboard(self):
        self._clear_ui()
        
        # Bind activity tracking
        self.bind_all("<Motion>", self._reset_activity)
        self.bind_all("<Key>", self._reset_activity)
        
        # Sidebar navigation
        self.sidebar = ctk.CTkFrame(
            self, width=88,
            fg_color=M3.SURFACE,
            corner_radius=0
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # App logo in sidebar
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=80)
        logo_frame.pack(fill="x")
        logo_frame.pack_propagate(False)
        ctk.CTkLabel(
            logo_frame, text="🔐",
            font=(M3.FONT_DISPLAY[0], 34)
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # Divider
        ctk.CTkFrame(self.sidebar, height=1, fg_color=M3.DIVIDER).pack(fill="x", padx=16)
        
        # Navigation items
        nav_container = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_container.pack(fill="x", pady=20)
        
        self.nav_buttons = {}
        nav_items = [
            ("files", "📁", "Files"),
            ("passwords", "🔑", "Passwords"),
            ("security", "🛡️", "Security"),
        ]
        
        for key, icon, label in nav_items:
            btn = ctk.CTkButton(
                nav_container,
                text=icon,
                width=54, height=54,
                corner_radius=M3.RADIUS_MEDIUM,
                fg_color="transparent",
                hover_color=M3.SURFACE_VARIANT,
                font=(M3.FONT_DISPLAY[0], 24),
                command=lambda k=key: self.set_tab(k)
            )
            btn.pack(pady=8)
            self.nav_buttons[key] = btn
        
        # Spacer
        ctk.CTkFrame(self.sidebar, fg_color="transparent").pack(expand=True, fill="y")
        
        # Lock button at bottom
        ctk.CTkButton(
            self.sidebar,
            text="🔒",
            width=54, height=54,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            font=(M3.FONT_DISPLAY[0], 22),
            command=self.lock_vault
        ).pack(pady=20)
        
        # Main content area
        self.main_container = ctk.CTkFrame(
            self,
            fg_color=M3.SURFACE_CONTAINER,
            corner_radius=M3.RADIUS_XLARGE
        )
        self.main_container.pack(side="right", expand=True, fill="both", padx=20, pady=20)
        
        # Split: Content + Preview
        self.content_area = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_area.pack(side="left", expand=True, fill="both")
        
        # Preview pane
        self.preview_pane = ctk.CTkFrame(
            self.main_container,
            width=400,
            corner_radius=M3.RADIUS_LARGE,
            fg_color=M3.SURFACE
        )
        self.preview_pane.pack(side="right", fill="y", padx=16, pady=16)
        self.preview_pane.pack_propagate(False)
        
        # Preview header
        preview_header = ctk.CTkFrame(self.preview_pane, fg_color="transparent")
        preview_header.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            preview_header,
            text="PREVIEW",
            font=(M3.FONT_BODY[0], 11, "bold"),
            text_color=M3.TEXT_TERTIARY
        ).pack()
        
        # Preview content area
        self.preview_content = ctk.CTkLabel(
            self.preview_pane,
            text="Select a file to preview",
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY,
            wraplength=340
        )
        self.preview_content.pack(expand=True, padx=24)
        
        # Load default tab
        self.set_tab("files")
    
    def set_tab(self, tab: str):
        self.current_tab = tab
        
        # Update navigation states
        for key, btn in self.nav_buttons.items():
            if key == tab:
                btn.configure(fg_color=M3.PRIMARY_CONTAINER)
            else:
                btn.configure(fg_color="transparent")
        
        # Clear content
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        # Render tab content
        if tab == "files":
            self._render_files_tab()
        elif tab == "passwords":
            self._render_passwords_tab()
        elif tab == "security":
            self._render_security_tab()
    
    def lock_vault(self):
        cleanup_temp_directory()
        self.is_unlocked = False
        self.unbind_all("<Motion>")
        self.unbind_all("<Key>")
        self.show_login()
        self.show_toast("Vault locked", "info")
    
    # ──────────────────────────────────────────────────────────────────────────
    # FILES TAB
    # ──────────────────────────────────────────────────────────────────────────
    def _render_files_tab(self):
        # Header
        header = ctk.CTkFrame(self.content_area, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 20))
        
        # Title and count
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text="Secure Files",
            font=(M3.FONT_DISPLAY[0], 30, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        file_count = len(list(VAULT_DIR.iterdir()))
        ctk.CTkLabel(
            title_frame,
            text=f"  ({file_count})",
            font=(M3.FONT_BODY[0], 16),
            text_color=M3.TEXT_TERTIARY
        ).pack(side="left", pady=(8, 0))
        
        # Add button
        ctk.CTkButton(
            header,
            text="+ Add File",
            width=130, height=44,
            corner_radius=22,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=self._upload_file
        ).pack(side="right")
        
        # File list
        scroll = ctk.CTkScrollableFrame(
            self.content_area,
            fg_color="transparent",
            scrollbar_button_color=M3.SURFACE_VARIANT,
            scrollbar_button_hover_color=M3.SURFACE_BRIGHT
        )
        scroll.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        
        files = list(VAULT_DIR.iterdir())
        
        if not files:
            # Empty state
            empty_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            empty_frame.pack(expand=True, pady=80)
            
            ctk.CTkLabel(
                empty_frame, text="📂",
                font=(M3.FONT_DISPLAY[0], 64)
            ).pack()
            
            ctk.CTkLabel(
                empty_frame,
                text="No files yet",
                font=(M3.FONT_BODY[0], 18, "bold"),
                text_color=M3.TEXT_SECONDARY
            ).pack(pady=(20, 8))
            
            ctk.CTkLabel(
                empty_frame,
                text="Click '+ Add File' to encrypt and store files securely",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_TERTIARY
            ).pack()
        else:
            # Sort by modification time (newest first)
            for file_path in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
                FileCard(
                    scroll,
                    file_path,
                    on_preview=self._show_file_preview,
                    on_open=self._open_file,
                    on_delete=self._delete_file
                ).pack(fill="x", pady=6, padx=12)
    
    def _upload_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[
                ("All files", "*.*"),
                ("Images", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("Documents", "*.txt *.pdf *.doc *.docx"),
                ("Code", "*.py *.js *.html *.css *.json")
            ]
        )
        
        if file_path:
            try:
                dest = VAULT_DIR / os.path.basename(file_path)
                crypto.encrypt_file(file_path, str(dest))
                self.show_toast("File encrypted and secured!", "success")
                self.set_tab("files")
            except Exception as e:
                self.show_toast(f"Error: {str(e)}", "error")
    
    def _show_file_preview(self, path: Path):
        try:
            with open(path, "rb") as f:
                data = crypto.decrypt(f.read())
            
            ext = path.suffix.lower()
            
            # Image preview
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
                img = Image.open(io.BytesIO(data))
                max_w, max_h = 340, 440
                ratio = min(max_w / img.width, max_h / img.height)
                new_size = (int(img.width * ratio), int(img.height * ratio))
                
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=new_size)
                self.preview_content.configure(image=ctk_img, text="")
            
            # Text preview
            elif ext in ['.txt', '.py', '.js', '.json', '.md', '.csv', '.html', '.css', '.xml']:
                text = data.decode('utf-8', errors='ignore')[:3000]
                self.preview_content.configure(
                    image="",
                    text=text,
                    font=(M3.FONT_MONO[0], 11),
                    justify="left"
                )
            
            # Unsupported format
            else:
                self.preview_content.configure(
                    image="",
                    text=f"Preview not available\nfor {ext.upper()} files\n\nClick 'Open' to view",
                    font=(M3.FONT_BODY[0], 14)
                )
                
        except Exception as e:
            self.preview_content.configure(
                image="",
                text=f"Preview error:\n{str(e)}"
            )
    
    def _open_file(self, path: Path):
        try:
            temp_path = TEMP_DIR / f"view_{path.name}"
            crypto.decrypt_file(str(path), str(temp_path))
            os.startfile(str(temp_path))
        except Exception as e:
            self.show_toast(f"Error opening file: {str(e)}", "error")
    
    def _delete_file(self, path: Path):
        def on_confirm():
            secure_delete(path)
            self.show_toast("File securely shredded", "success")
            self.set_tab("files")
        
        ConfirmDialog(
            self,
            title="🗑  Delete File?",
            message=f"This will permanently shred '{path.name}'. This action cannot be undone.",
            on_confirm=on_confirm,
            danger=True
        )
    
    # ──────────────────────────────────────────────────────────────────────────
    # PASSWORDS TAB
    # ──────────────────────────────────────────────────────────────────────────
    def _render_passwords_tab(self):
        # Header
        header = ctk.CTkFrame(self.content_area, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 20))
        
        ctk.CTkLabel(
            header,
            text="Password Vault",
            font=(M3.FONT_DISPLAY[0], 30, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        # Add password form
        form_container = ctk.CTkFrame(
            self.content_area,
            fg_color=M3.SURFACE,
            corner_radius=M3.RADIUS_LARGE
        )
        form_container.pack(fill="x", padx=32, pady=(0, 24))
        
        form = ctk.CTkFrame(form_container, fg_color="transparent")
        form.pack(fill="x", padx=20, pady=20)
        
        # Service name entry
        service_entry = ModernEntry(
            form,
            placeholder_text="Service name (e.g., Gmail, Netflix)"
        )
        service_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        
        # Password entry
        password_entry = ModernEntry(
            form,
            placeholder_text="Password",
            show="•"
        )
        password_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        
        # Generate button
        def generate_and_fill():
            pwd = generate_password(20)
            password_entry.delete(0, 'end')
            password_entry.insert(0, pwd)
            password_entry.configure(show="")  # Show generated password
            self.after(3000, lambda: password_entry.configure(show="•"))
        
        ctk.CTkButton(
            form, text="🎲", width=48, height=48,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.SECONDARY_CONTAINER,
            hover_color=M3.SECONDARY,
            font=(M3.FONT_BODY[0], 20),
            command=generate_and_fill
        ).pack(side="left", padx=(0, 10))
        
        # Save button
        def save_password():
            service = service_entry.get().strip()
            password = password_entry.get()
            
            if not service or not password:
                self.show_toast("Please fill in all fields", "warning")
                return
            
            passwords = self._load_passwords()
            passwords[service] = password
            self._save_passwords(passwords)
            
            service_entry.delete(0, 'end')
            password_entry.delete(0, 'end')
            self.show_toast("Password saved securely!", "success")
            self.set_tab("passwords")
        
        ctk.CTkButton(
            form, text="Save", width=90, height=48,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=save_password
        ).pack(side="left")
        
        # Password list
        scroll = ctk.CTkScrollableFrame(
            self.content_area,
            fg_color="transparent",
            scrollbar_button_color=M3.SURFACE_VARIANT,
            scrollbar_button_hover_color=M3.SURFACE_BRIGHT
        )
        scroll.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        
        passwords = self._load_passwords()
        
        if not passwords:
            # Empty state
            empty_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            empty_frame.pack(expand=True, pady=60)
            
            ctk.CTkLabel(
                empty_frame, text="🔑",
                font=(M3.FONT_DISPLAY[0], 56)
            ).pack()
            
            ctk.CTkLabel(
                empty_frame,
                text="No passwords saved",
                font=(M3.FONT_BODY[0], 18, "bold"),
                text_color=M3.TEXT_SECONDARY
            ).pack(pady=(20, 8))
            
            ctk.CTkLabel(
                empty_frame,
                text="Add your first password using the form above",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_TERTIARY
            ).pack()
        else:
            for service, pwd in sorted(passwords.items(), key=lambda x: x[0].lower()):
                PasswordCard(
                    scroll, service, pwd,
                    on_copy=self._copy_to_clipboard,
                    on_delete=self._delete_password
                ).pack(fill="x", pady=5, padx=12)
    
    def _load_passwords(self) -> dict:
        """Load and decrypt passwords from storage"""
        if not os.path.exists(PASSWORDS_DB):
            return {}
        try:
            with open(PASSWORDS_DB, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = crypto.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception:
            return {}
    
    def _save_passwords(self, passwords: dict) -> None:
        """Encrypt and save passwords to storage"""
        try:
            data = json.dumps(passwords).encode('utf-8')
            encrypted_data = crypto.encrypt(data)
            with open(PASSWORDS_DB, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            self.show_toast(f"Error saving: {str(e)}", "error")
    
    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard with visual feedback"""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.show_toast("Password copied to clipboard!", "success")
        
        # Auto-clear clipboard after 30 seconds for security
        def clear_clipboard():
            try:
                current = self.clipboard_get()
                if current == text:
                    self.clipboard_clear()
                    self.clipboard_append("")
            except:
                pass
        
        self.after(30000, clear_clipboard)
    
    def _delete_password(self, service: str) -> None:
        """Delete a password entry with confirmation"""
        def on_confirm():
            passwords = self._load_passwords()
            if service in passwords:
                del passwords[service]
                self._save_passwords(passwords)
                self.show_toast(f"Password for '{service}' deleted", "success")
                self.set_tab("passwords")
        
        ConfirmDialog(
            self,
            title="🗑  Delete Password?",
            message=f"Delete the saved password for '{service}'? This cannot be undone.",
            on_confirm=on_confirm,
            danger=True
        )
    
    # ──────────────────────────────────────────────────────────────────────────
    # SECURITY TAB (Intruder Logs)
    # ──────────────────────────────────────────────────────────────────────────
    def _render_security_tab(self):
        """Render the security/intruder logs tab"""
        # Header
        header = ctk.CTkFrame(self.content_area, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 20))
        
        # Title and count
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text="Security Center",
            font=(M3.FONT_DISPLAY[0], 30, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        intruder_count = len(list(INTRUDER_DIR.iterdir()))
        if intruder_count > 0:
            count_badge = ctk.CTkFrame(
                title_frame,
                width=32, height=24,
                corner_radius=12,
                fg_color=M3.ERROR
            )
            count_badge.pack(side="left", padx=(12, 0))
            count_badge.pack_propagate(False)
            
            ctk.CTkLabel(
                count_badge,
                text=str(intruder_count),
                font=(M3.FONT_BODY[0], 12, "bold"),
                text_color="#FFFFFF"
            ).place(relx=0.5, rely=0.5, anchor="center")
        
        # Clear all button
        if intruder_count > 0:
            ctk.CTkButton(
                header,
                text="Clear All Logs",
                width=130, height=44,
                corner_radius=22,
                fg_color=M3.ERROR_CONTAINER,
                hover_color=M3.ERROR,
                text_color=M3.ERROR,
                font=(M3.FONT_BODY[0], 14, "bold"),
                command=self._clear_all_intruders
            ).pack(side="right")
        
        # Stats panel
        stats_frame = ctk.CTkFrame(
            self.content_area,
            fg_color=M3.SURFACE,
            corner_radius=M3.RADIUS_LARGE
        )
        stats_frame.pack(fill="x", padx=32, pady=(0, 20))
        
        stats_inner = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_inner.pack(fill="x", padx=24, pady=20)
        
        # Stats items
        stats_data = [
            ("🛡️", "Vault Status", "Secured" if self.is_unlocked else "Locked", M3.SUCCESS),
            ("📁", "Protected Files", str(len(list(VAULT_DIR.iterdir()))), M3.PRIMARY),
            ("🔑", "Saved Passwords", str(len(self._load_passwords())), M3.SECONDARY),
            ("🚨", "Intrusion Attempts", str(intruder_count), M3.ERROR if intruder_count > 0 else M3.TEXT_TERTIARY)
        ]
        
        for icon, label, value, color in stats_data:
            stat_item = ctk.CTkFrame(stats_inner, fg_color="transparent")
            stat_item.pack(side="left", expand=True)
            
            ctk.CTkLabel(
                stat_item, text=icon,
                font=(M3.FONT_DISPLAY[0], 28)
            ).pack()
            
            ctk.CTkLabel(
                stat_item, text=value,
                font=(M3.FONT_DISPLAY[0], 24, "bold"),
                text_color=color
            ).pack(pady=(8, 2))
            
            ctk.CTkLabel(
                stat_item, text=label,
                font=(M3.FONT_BODY[0], 12),
                text_color=M3.TEXT_TERTIARY
            ).pack()
        
        # Section title for intruder logs
        if intruder_count > 0:
            ctk.CTkLabel(
                self.content_area,
                text="INTRUSION ATTEMPTS",
                font=(M3.FONT_BODY[0], 12, "bold"),
                text_color=M3.TEXT_TERTIARY
            ).pack(anchor="w", padx=36, pady=(10, 12))
        
        # Intruder list
        scroll = ctk.CTkScrollableFrame(
            self.content_area,
            fg_color="transparent",
            scrollbar_button_color=M3.SURFACE_VARIANT,
            scrollbar_button_hover_color=M3.SURFACE_BRIGHT
        )
        scroll.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        
        intruders = list(INTRUDER_DIR.iterdir())
        
        if not intruders:
            # Empty state
            empty_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            empty_frame.pack(expand=True, pady=50)
            
            ctk.CTkLabel(
                empty_frame, text="✅",
                font=(M3.FONT_DISPLAY[0], 56)
            ).pack()
            
            ctk.CTkLabel(
                empty_frame,
                text="No intrusion attempts",
                font=(M3.FONT_BODY[0], 18, "bold"),
                text_color=M3.SUCCESS
            ).pack(pady=(20, 8))
            
            ctk.CTkLabel(
                empty_frame,
                text="Your vault is secure. No unauthorized access attempts detected.",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_TERTIARY
            ).pack()
        else:
            # Sort by time (newest first)
            for intruder_path in sorted(intruders, key=lambda x: x.stat().st_mtime, reverse=True):
                IntruderCard(
                    scroll,
                    intruder_path,
                    on_view=self._view_intruder,
                    on_delete=self._delete_intruder
                ).pack(fill="x", pady=5, padx=12)
    
    def _view_intruder(self, path: Path) -> None:
        """Open intruder photo"""
        try:
            os.startfile(str(path))
        except Exception as e:
            self.show_toast(f"Error opening image: {str(e)}", "error")
    
    def _delete_intruder(self, path: Path) -> None:
        """Delete a single intruder log"""
        def on_confirm():
            try:
                path.unlink()
                self.show_toast("Intruder log deleted", "success")
                self.set_tab("security")
            except Exception as e:
                self.show_toast(f"Error: {str(e)}", "error")
        
        ConfirmDialog(
            self,
            title="Delete Log?",
            message="Delete this intrusion attempt log?",
            on_confirm=on_confirm,
            danger=False
        )
    
    def _clear_all_intruders(self) -> None:
        """Clear all intruder logs with confirmation"""
        def on_confirm():
            try:
                for file in INTRUDER_DIR.iterdir():
                    file.unlink()
                self.show_toast("All intruder logs cleared", "success")
                self.set_tab("security")
            except Exception as e:
                self.show_toast(f"Error: {str(e)}", "error")
        
        ConfirmDialog(
            self,
            title="🗑  Clear All Logs?",
            message="This will permanently delete all intrusion attempt photos. This cannot be undone.",
            on_confirm=on_confirm,
            danger=True
        )


# ══════════════════════════════════════════════════════════════════════════════
# SPLASH SCREEN (Optional - for a polished feel)
# ══════════════════════════════════════════════════════════════════════════════
class SplashScreen(ctk.CTkToplevel):
    """Loading splash screen shown at startup"""
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Window setup
        self.title("")
        self.geometry("400x300")
        self.configure(fg_color=M3.BG)
        self.overrideredirect(True)  # Remove window decorations
        self.resizable(False, False)
        
        # Center on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 300) // 2
        self.geometry(f"+{x}+{y}")
        
        # Content
        ctk.CTkLabel(
            self, text="🔐",
            font=(M3.FONT_DISPLAY[0], 72)
        ).pack(pady=(60, 20))
        
        ctk.CTkLabel(
            self, text=APP_NAME,
            font=(M3.FONT_DISPLAY[0], 32, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack()
        
        ctk.CTkLabel(
            self, text="Initializing secure environment...",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_TERTIARY
        ).pack(pady=(30, 0))
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(
            self,
            width=280,
            height=4,
            corner_radius=2,
            fg_color=M3.SURFACE_VARIANT,
            progress_color=M3.PRIMARY
        )
        self.progress.pack(pady=25)
        self.progress.set(0)
        
        # Animate progress
        self._animate_progress(0)
    
    def _animate_progress(self, value: float):
        if value <= 1.0:
            self.progress.set(value)
            self.after(20, lambda: self._animate_progress(value + 0.02))
        else:
            self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point for M3-VAULT"""
    # Configure CustomTkinter
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    # Create and run application
    app = VaultApp()
    
    # Show splash screen (optional - comment out if not needed)
    # splash = SplashScreen(app)
    # app.wait_window(splash)
    
    # Start main loop
    app.mainloop()


if __name__ == "__main__":
    main()