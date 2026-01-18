import os
import cv2
import time
import json
import string
import secrets
import threading
import io
import atexit
import shutil
import logging
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable, Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
from logging.handlers import RotatingFileHandler
from deepface import DeepFace
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import customtkinter as ctk
from tkinter import filedialog
from PIL import Image

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & ENVIRONMENT
# ══════════════════════════════════════════════════════════════════════════════
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

APP_NAME = "M3-VAULT"
VERSION = "2.2.0"

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class AppConfig:
    """Application configuration with defaults"""
    vault_dir: str = "vault_storage"
    intruder_dir: str = "intruders"
    temp_dir: str = ".vault_temp"
    key_file: str = "master.key"
    salt_file: str = "master.salt"
    master_face: str = "master_face.jpg"
    master_pin_hash: str = "master.pin"
    passwords_db: str = "passwords.vault"
    settings_file: str = "settings.json"
    log_file: str = "vault.log"
    
    auto_lock_minutes: int = 5
    clipboard_timeout: int = 30
    max_failed_attempts: int = 3
    secure_delete_passes: int = 3
    preview_visible: bool = True
    
    @classmethod
    def load(cls, config_file: str = "config.json") -> 'AppConfig':
        """Load configuration from file or use defaults"""
        if os.path.exists(config_file):
            try:
                with open(config_file) as f:
                    data = json.load(f)
                    return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
            except Exception:
                pass
        return cls()
    
    def save(self, config_file: str = "config.json") -> None:
        """Save configuration to file"""
        try:
            with open(config_file, "w") as f:
                json.dump(asdict(self), f, indent=2)
        except Exception:
            pass


config = AppConfig.load()

# Create directories
for directory in [config.vault_dir, config.intruder_dir, config.temp_dir]:
    Path(directory).mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
def setup_logging() -> logging.Logger:
    """Configure application logging with rotation"""
    logger = logging.getLogger('M3-VAULT')
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler with rotation (10MB max, 5 backups)
    file_handler = RotatingFileHandler(
        config.log_file,
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(console_handler)
    
    return logger


logger = setup_logging()


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
    
    # Primary Palette
    PRIMARY = "#58A6FF"
    PRIMARY_VARIANT = "#79C0FF"
    PRIMARY_CONTAINER = "#0D419D"
    ON_PRIMARY = "#002D6D"
    ON_PRIMARY_CONTAINER = "#D6E3FF"
    
    # Secondary Palette
    SECONDARY = "#BC8CFF"
    SECONDARY_CONTAINER = "#4A2F82"
    ON_SECONDARY = "#2D0A5E"
    
    # Tertiary Palette
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
    
    # Typography
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
# SETTINGS MANAGER
# ══════════════════════════════════════════════════════════════════════════════
class SettingsManager:
    """Manages application settings with atomic saves"""
    
    DEFAULT_SETTINGS = {
        "preview_visible": True,
        "auto_lock_minutes": 5,
        "clipboard_timeout": 30,
        "theme": "dark"
    }
    
    def __init__(self, settings_file: str):
        self.settings_file = settings_file
        self.settings = self._load_settings()
        self._lock = threading.Lock()
    
    def _load_settings(self) -> dict:
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    loaded = json.load(f)
                    return {**self.DEFAULT_SETTINGS, **loaded}
            except Exception as e:
                logger.warning(f"Failed to load settings: {e}")
        return self.DEFAULT_SETTINGS.copy()
    
    def save(self) -> None:
        """Atomically save settings to prevent corruption"""
        with self._lock:
            try:
                temp_file = f"{self.settings_file}.tmp"
                with open(temp_file, "w") as f:
                    json.dump(self.settings, f, indent=2)
                
                # Atomic replace
                if os.path.exists(self.settings_file):
                    backup = f"{self.settings_file}.backup"
                    shutil.copy2(self.settings_file, backup)
                
                shutil.move(temp_file, self.settings_file)
                logger.info("Settings saved successfully")
            except Exception as e:
                logger.error(f"Failed to save settings: {e}")
    
    def get(self, key: str, default=None):
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self.settings[key] = value
            self.save()


settings = SettingsManager(config.settings_file)


# ══════════════════════════════════════════════════════════════════════════════
# ENHANCED ENCRYPTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class CryptoEngine:
    """Handles encryption/decryption with key derivation from PIN"""
    
    def __init__(self, key_file: str, salt_file: str):
        self.key_file = key_file
        self.salt_file = salt_file
        self._cipher: Optional[Fernet] = None
        self._lock = threading.Lock()
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                return f.read()
        else:
            salt = secrets.token_bytes(32)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
            return salt
    
    def derive_key_from_pin(self, pin: str) -> bytes:
        """Derive encryption key from PIN using PBKDF2"""
        salt = self._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
        return key
    
    def initialize_with_pin(self, pin: str) -> bool:
        """Initialize cipher with PIN"""
        try:
            with self._lock:
                key = self.derive_key_from_pin(pin)
                self._cipher = Fernet(key)
                logger.info("Cipher initialized with PIN")
                return True
        except Exception as e:
            logger.error(f"Failed to initialize cipher: {e}")
            return False
    
    def set_master_pin(self, pin: str) -> bool:
        """Set the master PIN (hashed)"""
        try:
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            with open(config.master_pin_hash, "w") as f:
                f.write(pin_hash)
            self.initialize_with_pin(pin)
            logger.info("Master PIN set successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to set master PIN: {e}")
            return False
    
    def verify_pin(self, pin: str) -> bool:
        """Verify PIN against stored hash"""
        if not os.path.exists(config.master_pin_hash):
            return False
        
        try:
            with open(config.master_pin_hash, "r") as f:
                stored_hash = f.read().strip()
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            return secrets.compare_digest(pin_hash, stored_hash)
        except Exception as e:
            logger.error(f"PIN verification error: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if cipher is ready"""
        return self._cipher is not None
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        if not self._cipher:
            raise RuntimeError("Cipher not initialized")
        return self._cipher.encrypt(data)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        if not self._cipher:
            raise RuntimeError("Cipher not initialized")
        return self._cipher.decrypt(data)
    
    def encrypt_file(self, source: str, dest: str) -> None:
        """Encrypt file"""
        with open(source, "rb") as f:
            data = f.read()
        with open(dest, "wb") as f:
            f.write(self.encrypt(data))
        logger.info(f"Encrypted: {source} -> {dest}")
    
    def decrypt_file(self, source: str, dest: str) -> None:
        """Decrypt file"""
        with open(source, "rb") as f:
            data = f.read()
        with open(dest, "wb") as f:
            f.write(self.decrypt(data))
        logger.info(f"Decrypted: {source} -> {dest}")


crypto = CryptoEngine(config.key_file, config.salt_file)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════
def generate_password(
    length: int = 20,
    use_symbols: bool = True,
    use_uppercase: bool = True,
    use_numbers: bool = True
) -> str:
    """Generate a cryptographically secure password with guaranteed complexity"""
    chars = string.ascii_lowercase
    password = []
    
    if use_uppercase:
        chars += string.ascii_uppercase
        password.append(secrets.choice(string.ascii_uppercase))
    
    if use_numbers:
        chars += string.digits
        password.append(secrets.choice(string.digits))
    
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += symbols
        password.append(secrets.choice(symbols))
    
    # Fill remaining length
    password.extend(secrets.choice(chars) for _ in range(length - len(password)))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    
    logger.info(f"Generated secure password of length {length}")
    return ''.join(password)


def secure_delete(path: Path, passes: Optional[int] = None) -> None:
    """Securely delete a file by overwriting with random data"""
    if not path.exists():
        return
    
    passes = passes if passes is not None else config.secure_delete_passes
    size = path.stat().st_size
    
    try:
        with open(path, "r+b") as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        logger.info(f"Securely deleted: {path}")
    except Exception as e:
        logger.error(f"Secure delete failed for {path}: {e}")
        # Fallback to normal deletion
        try:
            path.unlink()
        except:
            pass


def format_file_size(size: float) -> str:
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
    temp_path = Path(config.temp_dir)
    if temp_path.exists():
        try:
            for file in temp_path.iterdir():
                secure_delete(file, passes=1)  # Quick wipe on exit
            logger.info("Temp directory cleaned up")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


atexit.register(cleanup_temp_directory)


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM WIDGETS
# ══════════════════════════════════════════════════════════════════════════════
class Toast(ctk.CTkFrame):
    """Material-style toast notification with auto-dismiss"""
    
    def __init__(self, parent, message: str, toast_type: str = "info", duration: int = 3500):
        super().__init__(parent, corner_radius=M3.RADIUS_MEDIUM)
        
        color_map = {
            "info": (M3.PRIMARY_CONTAINER, M3.PRIMARY, "ℹ️"),
            "success": (M3.SUCCESS_CONTAINER, M3.SUCCESS, "✅"),
            "error": (M3.ERROR_CONTAINER, M3.ERROR, "❌"),
            "warning": (M3.WARNING_CONTAINER, M3.WARNING, "⚠️")
        }
        
        bg_color, text_color, icon = color_map.get(toast_type, color_map["info"])
        
        self.configure(fg_color=bg_color, border_width=1, border_color=text_color)
        
        # Content container with proper padding
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(padx=20, pady=12, fill="x")
        
        # Icon with fixed alignment
        icon_label = ctk.CTkLabel(
            content,
            text=icon,
            font=(M3.FONT_BODY[0], 16),
            width=24,
            anchor="center"
        )
        icon_label.pack(side="left", padx=(0, 10))
        
        # Message
        ctk.CTkLabel(
            content,
            text=message,
            font=(M3.FONT_BODY[0], 13, "bold"),
            text_color=text_color,
            anchor="w"
        ).pack(side="left", fill="x", expand=True)
        
        # Position and animate
        self.place(relx=0.5, rely=0.92, anchor="center")
        self.lift()
        
        # Auto dismiss
        self.after(duration, self._fade_out)
    
    def _fade_out(self):
        try:
            self.destroy()
        except:
            pass


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
        
        ext = file_path.suffix.lower()
        icon = self._get_file_icon(ext)
        size = format_file_size(file_path.stat().st_size)
        
        # Main container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=16, pady=14)
        
        # Left section
        left_section = ctk.CTkFrame(container, fg_color="transparent")
        left_section.pack(side="left", fill="x", expand=True)
        
        # Icon with centered alignment
        icon_frame = ctk.CTkFrame(
            left_section, width=48, height=48,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.SURFACE_VARIANT
        )
        icon_frame.pack(side="left", padx=(0, 14))
        icon_frame.pack_propagate(False)
        icon_frame.grid_propagate(False)
        
        ctk.CTkLabel(
            icon_frame, text=icon,
            font=(M3.FONT_BODY[0], 24),
            anchor="center"
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
        
        ctk.CTkButton(
            actions, text="Preview", width=80, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 12),
            command=lambda: on_preview(file_path)
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            actions, text="Open", width=70, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 12, "bold"),
            command=lambda: on_open(file_path)
        ).pack(side="left", padx=4)
        
        ctk.CTkButton(
            actions, text="🗑️", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 16),
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
    """Password entry card with reveal, copy, and delete"""
    
    def __init__(self, master, service: str, password: str, on_copy, on_delete, **kwargs):
        super().__init__(master, fg_color=M3.SURFACE, corner_radius=M3.RADIUS_MEDIUM, **kwargs)
        
        self.password = password
        self.is_revealed = False
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=16, pady=12)
        
        # Left - Service info
        left = ctk.CTkFrame(container, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        
        # Service header with icon
        header = ctk.CTkFrame(left, fg_color="transparent")
        header.pack(anchor="w")
        
        # Service icon centered
        icon_container = ctk.CTkFrame(header, fg_color="transparent", width=28)
        icon_container.pack(side="left")
        icon_container.pack_propagate(False)
        
        ctk.CTkLabel(
            icon_container,
            text="🌐",
            font=(M3.FONT_BODY[0], 16),
            anchor="center"
        ).pack(expand=True)
        
        ctk.CTkLabel(
            header,
            text=service,
            font=(M3.FONT_BODY[0], 14, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left", padx=(4, 0))
        
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
            actions, text="👁️", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.SURFACE_VARIANT,
            hover_color=M3.SURFACE_BRIGHT,
            font=(M3.FONT_BODY[0], 16),
            command=self._toggle_reveal
        )
        self.reveal_btn.pack(side="left", padx=3)
        
        ctk.CTkButton(
            actions, text="Copy", width=65, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 12, "bold"),
            command=lambda: on_copy(password)
        ).pack(side="left", padx=3)
        
        ctk.CTkButton(
            actions, text="🗑️", width=36, height=36,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 16),
            command=lambda: on_delete(service)
        ).pack(side="left", padx=3)
        
        self.bind("<Enter>", lambda e: self.configure(fg_color=M3.SURFACE_CONTAINER_HIGH))
        self.bind("<Leave>", lambda e: self.configure(fg_color=M3.SURFACE))
    
    def _toggle_reveal(self):
        self.is_revealed = not self.is_revealed
        if self.is_revealed:
            self.password_label.configure(text=self.password)
            self.reveal_btn.configure(text="🙈")
        else:
            self.password_label.configure(text="•" * min(len(self.password), 20))
            self.reveal_btn.configure(text="👁️")


class IntruderCard(ctk.CTkFrame):
    """Card displaying intruder attempt information"""
    
    def __init__(self, master, file_path: Path, on_view, on_delete, **kwargs):
        super().__init__(master, fg_color=M3.SURFACE, corner_radius=M3.RADIUS_MEDIUM, **kwargs)
        
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
        
        # Alert icon centered
        icon_frame = ctk.CTkFrame(
            left, width=42, height=42,
            corner_radius=21,
            fg_color=M3.ERROR_CONTAINER
        )
        icon_frame.pack(side="left", padx=(0, 12))
        icon_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            icon_frame, text="🚨",
            font=(M3.FONT_BODY[0], 20),
            anchor="center"
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
            actions, text="🗑️", width=34, height=34,
            corner_radius=M3.RADIUS_SMALL,
            fg_color=M3.ERROR_CONTAINER,
            hover_color=M3.ERROR,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 16),
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


class UploadProgressDialog(ctk.CTkToplevel):
    """Progress dialog for multi-file upload"""
    
    def __init__(self, parent, total_files: int):
        super().__init__(parent)
        
        self.title("")
        self.geometry("480x280")
        self.configure(fg_color=M3.BG_ELEVATED)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Center on parent
        self.update()
        x = parent.winfo_x() + (parent.winfo_width() - 480) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 280) // 2
        self.geometry(f"+{x}+{y}")
        
        self.total_files = total_files
        self.current_file = 0
        self.successful = 0
        self.failed = 0
        
        # Icon centered
        icon_container = ctk.CTkFrame(self, fg_color="transparent", height=50)
        icon_container.pack(pady=(25, 15))
        
        ctk.CTkLabel(
            icon_container, text="🔐",
            font=(M3.FONT_DISPLAY[0], 40),
            anchor="center"
        ).pack()
        
        # Title
        self.title_label = ctk.CTkLabel(
            self, text="Encrypting Files...",
            font=(M3.FONT_DISPLAY[0], 20, "bold"),
            text_color=M3.TEXT_PRIMARY
        )
        self.title_label.pack(pady=(0, 8))
        
        # Current file label
        self.file_label = ctk.CTkLabel(
            self, text="Preparing...",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_SECONDARY,
            wraplength=400
        )
        self.file_label.pack(pady=(0, 20))
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(
            self,
            width=380,
            height=8,
            corner_radius=4,
            fg_color=M3.SURFACE_VARIANT,
            progress_color=M3.PRIMARY
        )
        self.progress.pack(pady=(0, 12))
        self.progress.set(0)
        
        # Progress text
        self.progress_text = ctk.CTkLabel(
            self, text=f"0 / {total_files} files",
            font=(M3.FONT_BODY[0], 12),
            text_color=M3.TEXT_TERTIARY
        )
        self.progress_text.pack()
    
    def update_progress(self, current: int, filename: str, success: bool = True):
        """Update the progress display"""
        self.current_file = current
        if success:
            self.successful += 1
        else:
            self.failed += 1
        
        progress_value = current / self.total_files
        self.progress.set(progress_value)
        self.file_label.configure(text=f"{'✅' if success else '❌'} {filename}")
        self.progress_text.configure(text=f"{current} / {self.total_files} files")
        self.update()
    
    def show_complete(self, on_close):
        """Show completion status"""
        self.title_label.configure(
            text="Upload Complete!",
            text_color=M3.SUCCESS if self.failed == 0 else M3.WARNING
        )
        
        status_text = f"✅ {self.successful} files encrypted successfully"
        if self.failed > 0:
            status_text += f"\n❌ {self.failed} files failed"
        
        self.file_label.configure(
            text=status_text,
            text_color=M3.SUCCESS if self.failed == 0 else M3.TEXT_SECONDARY
        )
        
        self.progress_text.pack_forget()
        
        ctk.CTkButton(
            self, text="Done", width=120, height=40,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=lambda: [on_close(), self.destroy()]
        ).pack(pady=15)


class DropZone(ctk.CTkFrame):
    """Drag and drop zone for file uploads"""
    
    def __init__(self, master, on_click, **kwargs):
        super().__init__(
            master,
            fg_color=M3.SURFACE,
            corner_radius=M3.RADIUS_LARGE,
            border_width=2,
            border_color=M3.OUTLINE,
            **kwargs
        )
        
        self.on_click = on_click
        self.default_border = M3.OUTLINE
        self.hover_border = M3.PRIMARY
        
        self.bind("<Button-1>", lambda e: on_click())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        
        # Content container
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(expand=True, pady=30)
        content.bind("<Button-1>", lambda e: on_click())
        
        # Icon centered
        icon_container = ctk.CTkFrame(content, fg_color="transparent", height=60)
        icon_container.pack()
        
        icon_label = ctk.CTkLabel(
            icon_container, text="📁",
            font=(M3.FONT_DISPLAY[0], 48),
            anchor="center"
        )
        icon_label.pack()
        icon_label.bind("<Button-1>", lambda e: on_click())
        
        # Primary text
        primary_label = ctk.CTkLabel(
            content,
            text="Click to upload files",
            font=(M3.FONT_BODY[0], 16, "bold"),
            text_color=M3.TEXT_PRIMARY
        )
        primary_label.pack(pady=(15, 5))
        primary_label.bind("<Button-1>", lambda e: on_click())
        
        # Secondary text
        secondary_label = ctk.CTkLabel(
            content,
            text="Select one or multiple files to encrypt",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_TERTIARY
        )
        secondary_label.pack()
        secondary_label.bind("<Button-1>", lambda e: on_click())
        
        # Supported formats
        formats_label = ctk.CTkLabel(
            content,
            text="Images • Documents • Videos • Archives • Any file type",
            font=(M3.FONT_BODY[0], 11),
            text_color=M3.TEXT_DISABLED
        )
        formats_label.pack(pady=(15, 0))
        formats_label.bind("<Button-1>", lambda e: on_click())
    
    def _on_enter(self, event):
        self.configure(border_color=self.hover_border, fg_color=M3.SURFACE_VARIANT)
    
    def _on_leave(self, event):
        self.configure(border_color=self.default_border, fg_color=M3.SURFACE)


class PreviewPane(ctk.CTkFrame):
    """Collapsible preview pane"""
    
    def __init__(self, master, on_close, **kwargs):
        super().__init__(
            master,
            width=400,
            corner_radius=M3.RADIUS_LARGE,
            fg_color=M3.SURFACE,
            **kwargs
        )
        self.pack_propagate(False)
        
        self.on_close = on_close
        self.current_file = None
        
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 0))
        
        ctk.CTkLabel(
            header,
            text="PREVIEW",
            font=(M3.FONT_BODY[0], 11, "bold"),
            text_color=M3.TEXT_TERTIARY
        ).pack(side="left")
        
        # Close button
        close_btn = ctk.CTkButton(
            header,
            text="✕",
            width=32, height=32,
            corner_radius=16,
            fg_color="transparent",
            hover_color=M3.SURFACE_VARIANT,
            text_color=M3.TEXT_SECONDARY,
            font=(M3.FONT_BODY[0], 16),
            command=on_close
        )
        close_btn.pack(side="right")
        
        # Divider
        ctk.CTkFrame(
            self, height=1,
            fg_color=M3.DIVIDER
        ).pack(fill="x", padx=16, pady=12)
        
        # File info section
        self.file_info_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_info_frame.pack(fill="x", padx=20)
        
        self.file_name_label = ctk.CTkLabel(
            self.file_info_frame,
            text="",
            font=(M3.FONT_BODY[0], 14, "bold"),
            text_color=M3.TEXT_PRIMARY,
            wraplength=340
        )
        self.file_name_label.pack(anchor="w")
        
        self.file_meta_label = ctk.CTkLabel(
            self.file_info_frame,
            text="",
            font=(M3.FONT_BODY[0], 12),
            text_color=M3.TEXT_TERTIARY
        )
        self.file_meta_label.pack(anchor="w", pady=(2, 0))
        
        # Preview content area
        self.preview_container = ctk.CTkFrame(self, fg_color="transparent")
        self.preview_container.pack(expand=True, fill="both", padx=16, pady=16)
        
        self.preview_content = ctk.CTkLabel(
            self.preview_container,
            text="Select a file to preview",
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY,
            wraplength=340
        )
        self.preview_content.pack(expand=True)
        
        # Initially hide file info
        self.file_info_frame.pack_forget()
    
    def show_preview(self, path: Path, data: Optional[bytes] = None, error: Optional[str] = None):
        """Display preview for a file"""
        self.current_file = path
        
        # Show file info
        self.file_info_frame.pack(fill="x", padx=20, before=self.preview_container)
        self.file_name_label.configure(text=path.name)
        
        ext = path.suffix.lower()
        size = format_file_size(path.stat().st_size)
        self.file_meta_label.configure(text=f"{size}  •  {ext.upper()[1:] if ext else 'FILE'}")
        
        # Clear previous preview
        self.preview_content.configure(image="", text="")
        
        if error:
            self.preview_content.configure(
                text=f"Preview error:\n{error}",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.ERROR
            )
            return
        
        if data is None:
            self.preview_content.configure(
                text="Loading preview...",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_SECONDARY
            )
            return
        
        # Image preview
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            try:
                img = Image.open(io.BytesIO(data))
                max_w, max_h = 340, 380
                ratio = min(max_w / img.width, max_h / img.height)
                new_size = (int(img.width * ratio), int(img.height * ratio))
                
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=new_size)
                self.preview_content.configure(image=ctk_img, text="")
            except Exception as e:
                self.preview_content.configure(
                    text=f"Could not load image:\n{str(e)}",
                    font=(M3.FONT_BODY[0], 13),
                    text_color=M3.ERROR
                )
        
        # Text preview
        elif ext in ['.txt', '.py', '.js', '.json', '.md', '.csv', '.html', '.css', '.xml']:
            try:
                text = data.decode('utf-8', errors='ignore')[:3000]
                if len(data) > 3000:
                    text += "\n\n... (truncated)"
                self.preview_content.configure(
                    image="",
                    text=text,
                    font=(M3.FONT_MONO[0], 11),
                    text_color=M3.TEXT_PRIMARY,
                    justify="left"
                )
            except Exception as e:
                self.preview_content.configure(
                    text=f"Could not read text:\n{str(e)}",
                    font=(M3.FONT_BODY[0], 13),
                    text_color=M3.ERROR
                )
        else:
            self.preview_content.configure(
                image="",
                text=f"Preview not available\nfor {ext.upper()} files\n\nClick 'Open' to view\nwith default application",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_SECONDARY
            )
    
    def clear_preview(self):
        """Clear the preview"""
        self.current_file = None
        self.file_info_frame.pack_forget()
        self.preview_content.configure(
            image="",
            text="Select a file to preview",
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY
        )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class VaultApp(ctk.CTk):
    """Main M3-VAULT Application with enhanced security"""
    
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title(APP_NAME)
        self.geometry("1350x850")
        self.configure(fg_color=M3.BG)
        self.minsize(1100, 700)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # State
        self.is_unlocked = False
        self.current_tab = "files"
        self.last_activity = time.time()
        self.preview_visible = settings.get("preview_visible", True)
        self.failed_attempts = 0
        
        # Thread safety
        self.camera_lock = threading.Lock()
        
        # Show login screen
        self.show_login()
        
        # Start inactivity checker
        self._check_inactivity()
        
        logger.info("Application started")
    
    def _check_inactivity(self):
        """Auto-lock after configured minutes of inactivity"""
        if self.is_unlocked:
            timeout = settings.get("auto_lock_minutes", 5) * 60
            if (time.time() - self.last_activity) > timeout:
                logger.info("Auto-lock triggered due to inactivity")
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
        
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo container with centered icon
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
            font=(M3.FONT_DISPLAY[0], 52),
            anchor="center"
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
        
        # Check if first time setup
        is_first_time = not os.path.exists(config.master_face) or not os.path.exists(config.master_pin_hash)
        
        if is_first_time:
            self._show_setup_screen(bg_frame)
        else:
            self._show_auth_screen(bg_frame)
    
    def _show_setup_screen(self, parent):
        """First-time setup for Face ID and PIN"""
        ctk.CTkLabel(
            parent,
            text="First Time Setup",
            font=(M3.FONT_BODY[0], 18, "bold"),
            text_color=M3.PRIMARY
        ).pack(pady=(0, 20))
        
        # PIN entry
        pin_frame = ctk.CTkFrame(parent, fg_color="transparent")
        pin_frame.pack(pady=10)
        
        ctk.CTkLabel(
            pin_frame,
            text="Create a Master PIN (4-8 digits):",
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY
        ).pack(pady=(0, 8))
        
        pin_entry = ModernEntry(
            pin_frame,
            placeholder_text="Enter PIN",
            show="•",
            width=250
        )
        pin_entry.pack()
        
        confirm_pin_entry = ModernEntry(
            pin_frame,
            placeholder_text="Confirm PIN",
            show="•",
            width=250
        )
        confirm_pin_entry.pack(pady=(8, 0))
        
        # Status label
        self.setup_status = ctk.CTkLabel(
            parent, text="",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_SECONDARY
        )
        self.setup_status.pack(pady=15)
        
        # Setup button
        def complete_setup():
            pin = pin_entry.get().strip()
            confirm_pin = confirm_pin_entry.get().strip()
            
            if not pin or not confirm_pin:
                self.show_toast("Please enter PIN in both fields", "warning")
                return
            
            if pin != confirm_pin:
                self.show_toast("PINs do not match", "error")
                return
            
            if len(pin) < 4 or len(pin) > 8 or not pin.isdigit():
                self.show_toast("PIN must be 4-8 digits", "warning")
                return
            
            # Set PIN
            if not crypto.set_master_pin(pin):
                self.show_toast("Failed to set PIN", "error")
                return
            
            # Capture face
            self.setup_status.configure(text="📸 Capturing your face... Look at the camera")
            
            def capture_face():
                with self.camera_lock:
                    cap = None
                    try:
                        cap = cv2.VideoCapture(0)
                        if not cap.isOpened():
                            raise RuntimeError("Camera not available")
                        
                        time.sleep(0.5)
                        ret, frame = cap.read()
                        
                        if not ret:
                            raise RuntimeError("Failed to capture frame")
                        
                        cv2.imwrite(config.master_face, frame)
                        logger.info("Face ID registered successfully")
                        
                        self.after(0, lambda: self.show_toast("Setup complete!", "success"))
                        self.after(1000, self.show_login)
                        
                    except Exception as e:
                        logger.error(f"Face capture failed: {e}")
                        self.after(0, lambda: self.show_toast(f"Camera error: {str(e)}", "error"))
                    finally:
                        if cap:
                            cap.release()
                        cv2.destroyAllWindows()
            
            threading.Thread(target=capture_face, daemon=True).start()
        
        ctk.CTkButton(
            parent,
            text="Complete Setup",
            width=250, height=50,
            corner_radius=25,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 16, "bold"),
            command=complete_setup
        ).pack(pady=15)
    
    def _show_auth_screen(self, parent):
        """Authentication screen for existing users"""
        # PIN entry
        pin_frame = ctk.CTkFrame(parent, fg_color="transparent")
        pin_frame.pack(pady=15)
        
        ctk.CTkLabel(
            pin_frame,
            text="Enter Master PIN:",
            font=(M3.FONT_BODY[0], 14),
            text_color=M3.TEXT_SECONDARY
        ).pack(pady=(0, 8))
        
        pin_entry = ModernEntry(
            pin_frame,
            placeholder_text="PIN",
            show="•",
            width=250
        )
        pin_entry.pack()
        
        # Status label
        self.status_label = ctk.CTkLabel(
            parent, text="",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_SECONDARY
        )
        self.status_label.pack(pady=18)
        
        # Unlock button
        def attempt_unlock():
            pin = pin_entry.get().strip()
            
            if not pin:
                self.show_toast("Please enter your PIN", "warning")
                return
            
            if not crypto.verify_pin(pin):
                self.failed_attempts += 1
                logger.warning(f"Failed PIN attempt ({self.failed_attempts})")
                
                if self.failed_attempts >= config.max_failed_attempts:
                    self.show_toast("Too many failed attempts. Verifying with Face ID...", "error")
                    self._start_auth_thread(pin)
                else:
                    self.show_toast(f"Incorrect PIN ({self.failed_attempts}/{config.max_failed_attempts})", "error")
                return
            
            # PIN correct, initialize crypto
            if not crypto.initialize_with_pin(pin):
                self.show_toast("Failed to initialize encryption", "error")
                return
            
            # Now verify face
            self._start_auth_thread(pin)
        
        # Handle Enter key
        pin_entry.bind("<Return>", lambda e: attempt_unlock())
        
        self.unlock_btn = ctk.CTkButton(
            parent,
            text="🔓  Unlock with Face ID",
            width=300, height=60,
            corner_radius=30,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 17, "bold"),
            command=attempt_unlock
        )
        self.unlock_btn.pack(pady=12)
        
        # Reset PIN option
        reset_frame = ctk.CTkFrame(parent, fg_color="transparent")
        reset_frame.pack(pady=15)
        
        ctk.CTkLabel(
            reset_frame,
            text="Forgot PIN? ",
            font=(M3.FONT_BODY[0], 13),
            text_color=M3.TEXT_TERTIARY
        ).pack(side="left")
        
        ctk.CTkButton(
            reset_frame,
            text="Reset Vault",
            fg_color="transparent",
            hover_color=M3.SURFACE_VARIANT,
            text_color=M3.ERROR,
            font=(M3.FONT_BODY[0], 13, "bold"),
            command=self._reset_vault
        ).pack(side="left")
    
    def _start_auth_thread(self, pin: str):
        """Start face authentication in background thread"""
        if not os.path.exists(config.master_face):
            self.show_toast("Face ID not registered", "error")
            return
        
        self.unlock_btn.configure(state="disabled", text="🔄  Scanning...")
        self.status_label.configure(text="Look at the camera", text_color=M3.TEXT_SECONDARY)
        threading.Thread(target=self._run_authentication, args=(pin,), daemon=True).start()
    
    def _run_authentication(self, pin: str):
        """Run face authentication with camera lock"""
        with self.camera_lock:
            cap = None
            temp_img = None
            
            try:
                cap = cv2.VideoCapture(0)
                if not cap.isOpened():
                    raise RuntimeError("Camera not available")
                
                time.sleep(0.3)
                ret, frame = cap.read()
                
                if not ret:
                    raise RuntimeError("Failed to capture frame")
                
                temp_img = Path(config.temp_dir) / f"auth_{int(time.time())}.jpg"
                cv2.imwrite(str(temp_img), frame)
                
                result = DeepFace.verify(
                    str(temp_img), config.master_face,
                    enforce_detection=True,
                    detector_backend='opencv',
                    model_name='VGG-Face'
                )
                
                if result['verified']:
                    self.is_unlocked = True
                    self.failed_attempts = 0
                    logger.info("Authentication successful")
                    self.after(0, self.show_dashboard)
                    self.after(0, lambda: self.show_toast("Welcome back!", "success"))
                else:
                    # Log intruder
                    intruder_file = Path(config.intruder_dir) / f"intruder_{int(time.time())}.jpg"
                    shutil.copy(temp_img, intruder_file)
                    logger.warning("Intruder detected and logged")
                    self.after(0, lambda: self.show_toast("Access Denied • Intruder logged", "error"))
                    self.after(0, self._reset_auth_button)
                    
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Authentication error: {e}")
                
                if "Face" in error_msg or "detect" in error_msg.lower():
                    self.after(0, lambda: self.show_toast("No face detected • Ensure good lighting", "warning"))
                else:
                    self.after(0, lambda: self.show_toast(f"Auth error: {error_msg[:50]}", "error"))
                self.after(0, self._reset_auth_button)
                
            finally:
                if cap:
                    cap.release()
                cv2.destroyAllWindows()
                
                if temp_img and temp_img.exists():
                    try:
                        temp_img.unlink()
                    except:
                        pass
    
    def _reset_auth_button(self):
        try:
            self.unlock_btn.configure(state="normal", text="🔓  Unlock with Face ID")
            self.status_label.configure(text="")
        except:
            pass
    
    def _reset_vault(self):
        """Reset vault (WARNING: deletes all data)"""
        def on_confirm():
            try:
                # Delete all vault data
                for file in Path(config.vault_dir).iterdir():
                    secure_delete(file, passes=1)
                
                # Delete auth files
                for file in [config.master_face, config.master_pin_hash, config.key_file, 
                            config.salt_file, config.passwords_db]:
                    path = Path(file)
                    if path.exists():
                        secure_delete(path, passes=1)
                
                logger.info("Vault reset completed")
                self.show_toast("Vault reset complete", "success")
                self.after(1000, self.show_login)
                
            except Exception as e:
                logger.error(f"Reset failed: {e}")
                self.show_toast(f"Reset failed: {str(e)}", "error")
        
        ConfirmDialog(
            self,
            title="⚠️  Reset Vault?",
            message="This will DELETE ALL vault data, passwords, and settings. This cannot be undone!",
            on_confirm=on_confirm,
            danger=True
        )
    
    # ──────────────────────────────────────────────────────────────────────────
    # DASHBOARD
    # ──────────────────────────────────────────────────────────────────────────
    def show_dashboard(self):
        self._clear_ui()
        
        # Bind activity tracking
        self.bind_all("<Motion>", self._reset_activity)
        self.bind_all("<Key>", self._reset_activity)
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(
            self, width=88,
            fg_color=M3.SURFACE,
            corner_radius=0
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # Logo centered
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=80)
        logo_frame.pack(fill="x")
        logo_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            logo_frame, text="🔐",
            font=(M3.FONT_DISPLAY[0], 34),
            anchor="center"
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # Divider
        ctk.CTkFrame(self.sidebar, height=1, fg_color=M3.DIVIDER).pack(fill="x", padx=16)
        
        # Navigation
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
        
        # Lock button
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
        
        # Main content
        self.main_container = ctk.CTkFrame(
            self,
            fg_color=M3.SURFACE_CONTAINER,
            corner_radius=M3.RADIUS_XLARGE
        )
        self.main_container.pack(side="right", expand=True, fill="both", padx=20, pady=20)
        
        # Content area
        self.content_area = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_area.pack(side="left", expand=True, fill="both")
        
        # Preview pane
        self.preview_pane = PreviewPane(
            self.main_container,
            on_close=self.toggle_preview
        )
        
        if self.preview_visible:
            self.preview_pane.pack(side="right", fill="y", padx=16, pady=16)
        
        # Show preview button
        self.show_preview_btn = ctk.CTkButton(
            self.main_container,
            text="◀ Preview",
            width=100, height=36,
            corner_radius=18,
            fg_color=M3.SURFACE,
            hover_color=M3.SURFACE_VARIANT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 12),
            command=self.toggle_preview
        )
        
        if not self.preview_visible:
            self.show_preview_btn.place(relx=0.98, rely=0.5, anchor="e")
        
        self.set_tab("files")
    
    def toggle_preview(self):
        """Toggle preview pane"""
        self.preview_visible = not self.preview_visible
        settings.set("preview_visible", self.preview_visible)
        
        if self.preview_visible:
            self.show_preview_btn.place_forget()
            self.preview_pane.pack(side="right", fill="y", padx=16, pady=16)
            self.show_toast("Preview panel opened", "info")
        else:
            self.preview_pane.pack_forget()
            self.show_preview_btn.place(relx=0.98, rely=0.5, anchor="e")
            self.show_toast("Preview panel closed", "info")
    
    def set_tab(self, tab: str):
        self.current_tab = tab
        
        # Update navigation
        for key, btn in self.nav_buttons.items():
            if key == tab:
                btn.configure(fg_color=M3.PRIMARY_CONTAINER)
            else:
                btn.configure(fg_color="transparent")
        
        # Clear content
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        if hasattr(self, 'preview_pane'):
            self.preview_pane.clear_preview()
        
        # Render tab
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
        logger.info("Vault locked")
        self.show_login()
        self.show_toast("Vault locked", "info")
    
    # ──────────────────────────────────────────────────────────────────────────
    # FILES TAB
    # ──────────────────────────────────────────────────────────────────────────
    def _render_files_tab(self):
        # Header
        header = ctk.CTkFrame(self.content_area, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 20))
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text="Secure Files",
            font=(M3.FONT_DISPLAY[0], 30, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        file_count = len(list(Path(config.vault_dir).iterdir()))
        ctk.CTkLabel(
            title_frame,
            text=f"  ({file_count})",
            font=(M3.FONT_BODY[0], 16),
            text_color=M3.TEXT_TERTIARY
        ).pack(side="left", pady=(8, 0))
        
        # Action buttons
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        
        preview_btn_text = "Hide Preview" if self.preview_visible else "Show Preview"
        ctk.CTkButton(
            btn_frame,
            text=f"👁️ {preview_btn_text}",
            width=130, height=44,
            corner_radius=22,
            fg_color=M3.SURFACE,
            hover_color=M3.SURFACE_VARIANT,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 13),
            command=self.toggle_preview
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_frame,
            text="➕ Add Files",
            width=130, height=44,
            corner_radius=22,
            fg_color=M3.PRIMARY,
            hover_color=M3.PRIMARY_VARIANT,
            text_color=M3.ON_PRIMARY,
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=self._upload_files
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_frame,
            text="📁 Add Folder",
            width=130, height=44,
            corner_radius=22,
            fg_color=M3.SECONDARY_CONTAINER,
            hover_color=M3.SECONDARY,
            text_color=M3.TEXT_PRIMARY,
            font=(M3.FONT_BODY[0], 14, "bold"),
            command=self._upload_folder
        ).pack(side="left")
        
        files = list(Path(config.vault_dir).iterdir())
        
        if not files:
            drop_zone = DropZone(
                self.content_area,
                on_click=self._upload_files
            )
            drop_zone.pack(expand=True, fill="both", padx=32, pady=(10, 32))
        else:
            # Compact drop zone
            compact_drop = ctk.CTkFrame(
                self.content_area,
                fg_color=M3.SURFACE,
                corner_radius=M3.RADIUS_MEDIUM,
                height=70
            )
            compact_drop.pack(fill="x", padx=32, pady=(0, 15))
            compact_drop.pack_propagate(False)
            compact_drop.bind("<Button-1>", lambda e: self._upload_files())
            compact_drop.bind("<Enter>", lambda e: compact_drop.configure(fg_color=M3.SURFACE_VARIANT))
            compact_drop.bind("<Leave>", lambda e: compact_drop.configure(fg_color=M3.SURFACE))
            
            drop_content = ctk.CTkFrame(compact_drop, fg_color="transparent")
            drop_content.place(relx=0.5, rely=0.5, anchor="center")
            drop_content.bind("<Button-1>", lambda e: self._upload_files())
            
            ctk.CTkLabel(
                drop_content,
                text="📁  Click to add more files",
                font=(M3.FONT_BODY[0], 14),
                text_color=M3.TEXT_SECONDARY
            ).pack(side="left")
            
            # File list
            scroll = ctk.CTkScrollableFrame(
                self.content_area,
                fg_color="transparent",
                scrollbar_button_color=M3.SURFACE_VARIANT,
                scrollbar_button_hover_color=M3.SURFACE_BRIGHT
            )
            scroll.pack(expand=True, fill="both", padx=20, pady=(0, 20))
            
            for file_path in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
                FileCard(
                    scroll,
                    file_path,
                    on_preview=self._show_file_preview,
                    on_open=self._open_file,
                    on_delete=self._delete_file
                ).pack(fill="x", pady=6, padx=12)
    
    def _upload_files(self):
        file_paths = filedialog.askopenfilenames(title="Select files to encrypt")
        
        if not file_paths:
            return
        
        threading.Thread(
            target=self._process_file_uploads,
            args=(file_paths,),
            daemon=True
        ).start()
    
    def _upload_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder to encrypt")
        
        if not folder_path:
            return
        
        folder = Path(folder_path)
        file_paths = [str(f) for f in folder.iterdir() if f.is_file()]
        
        if not file_paths:
            self.show_toast("No files found in folder", "warning")
            return
        
        threading.Thread(
            target=self._process_file_uploads,
            args=(tuple(file_paths),),
            daemon=True
        ).start()
    
    def _process_file_uploads(self, file_paths: tuple):
        total_files = len(file_paths)
        self.after(0, lambda: self._show_upload_progress(total_files))
        time.sleep(0.1)
        
        successful = 0
        failed = 0
        
        for i, file_path in enumerate(file_paths, 1):
            filename = os.path.basename(file_path)
            
            try:
                dest = Path(config.vault_dir) / filename
                
                # Handle duplicates
                if dest.exists():
                    name, ext = os.path.splitext(filename)
                    counter = 1
                    while dest.exists():
                        dest = Path(config.vault_dir) / f"{name}_{counter}{ext}"
                        counter += 1
                
                crypto.encrypt_file(file_path, str(dest))
                successful += 1
                self.after(0, lambda i=i, fn=filename: self._update_upload_progress(i, fn, True))
                
            except Exception as e:
                logger.error(f"Failed to encrypt {filename}: {e}")
                failed += 1
                self.after(0, lambda i=i, fn=filename: self._update_upload_progress(i, fn, False))
            
            time.sleep(0.05)
        
        self.after(0, lambda: self._complete_upload(successful, failed))
    
    def _show_upload_progress(self, total_files: int):
        self.upload_dialog = UploadProgressDialog(self, total_files)
    
    def _update_upload_progress(self, current: int, filename: str, success: bool):
        if hasattr(self, 'upload_dialog') and self.upload_dialog.winfo_exists():
            self.upload_dialog.update_progress(current, filename, success)
    
    def _complete_upload(self, successful: int, failed: int):
        if hasattr(self, 'upload_dialog') and self.upload_dialog.winfo_exists():
            self.upload_dialog.show_complete(lambda: self.set_tab("files"))
        else:
            self.set_tab("files")
        
        if successful > 0:
            msg = f"{successful} file{'s' if successful > 1 else ''} encrypted successfully"
            if failed > 0:
                msg += f" ({failed} failed)"
            self.show_toast(msg, "success" if failed == 0 else "warning")
    
    def _show_file_preview(self, path: Path):
        if not self.preview_visible:
            self.toggle_preview()
        
        try:
            with open(path, "rb") as f:
                data = crypto.decrypt(f.read())
            self.preview_pane.show_preview(path, data)
        except Exception as e:
            logger.error(f"Preview failed for {path}: {e}")
            self.preview_pane.show_preview(path, error=str(e))
    
    def _open_file(self, path: Path):
        try:
            temp_path = Path(config.temp_dir) / f"view_{int(time.time())}_{path.name}"
            crypto.decrypt_file(str(path), str(temp_path))
            os.startfile(str(temp_path))
            
            # Schedule cleanup after 5 minutes
            def cleanup():
                time.sleep(300)
                if temp_path.exists():
                    secure_delete(temp_path, passes=1)
            
            threading.Thread(target=cleanup, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Failed to open file: {e}")
            self.show_toast(f"Error opening file: {str(e)}", "error")
    
    def _delete_file(self, path: Path):
        def on_confirm():
            secure_delete(path)
            self.show_toast("File securely shredded", "success")
            self.preview_pane.clear_preview()
            self.set_tab("files")
        
        ConfirmDialog(
            self,
            title="🗑️  Delete File?",
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
        
        service_entry = ModernEntry(
            form,
            placeholder_text="Service name (e.g., Gmail, Netflix)"
        )
        service_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        
        password_entry = ModernEntry(
            form,
            placeholder_text="Password",
            show="•"
        )
        password_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        
        def generate_and_fill():
            pwd = generate_password(20)
            password_entry.delete(0, 'end')
            password_entry.insert(0, pwd)
            password_entry.configure(show="")
            self.after(3000, lambda: password_entry.configure(show="•"))
        
        ctk.CTkButton(
            form, text="🎲", width=48, height=48,
            corner_radius=M3.RADIUS_MEDIUM,
            fg_color=M3.SECONDARY_CONTAINER,
            hover_color=M3.SECONDARY,
            font=(M3.FONT_BODY[0], 20),
            command=generate_and_fill
        ).pack(side="left", padx=(0, 10))
        
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
            empty_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            empty_frame.pack(expand=True, pady=60)
            
            ctk.CTkLabel(
                empty_frame, text="🔑",
                font=(M3.FONT_DISPLAY[0], 56),
                anchor="center"
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
        if not os.path.exists(config.passwords_db):
            return {}
        try:
            with open(config.passwords_db, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = crypto.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to load passwords: {e}")
            return {}
    
    def _save_passwords(self, passwords: dict) -> None:
        try:
            data = json.dumps(passwords).encode('utf-8')
            encrypted_data = crypto.encrypt(data)
            
            # Atomic write
            temp_file = f"{config.passwords_db}.tmp"
            with open(temp_file, "wb") as f:
                f.write(encrypted_data)
            
            if os.path.exists(config.passwords_db):
                shutil.copy2(config.passwords_db, f"{config.passwords_db}.backup")
            
            shutil.move(temp_file, config.passwords_db)
            logger.info("Passwords saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save passwords: {e}")
            self.show_toast(f"Error saving: {str(e)}", "error")
    
    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.show_toast("Password copied to clipboard!", "success")
        
        # Auto-clear after timeout
        def clear_clipboard():
            try:
                current = self.clipboard_get()
                if current == text:
                    self.clipboard_clear()
                    self.clipboard_append("")
            except:
                pass
        
        timeout = (settings.get("clipboard_timeout") or 30) * 1000
        self.after(timeout, clear_clipboard)
    
    def _delete_password(self, service: str) -> None:
        def on_confirm():
            passwords = self._load_passwords()
            if service in passwords:
                del passwords[service]
                self._save_passwords(passwords)
                self.show_toast(f"Password for '{service}' deleted", "success")
                self.set_tab("passwords")
        
        ConfirmDialog(
            self,
            title="🗑️  Delete Password?",
            message=f"Delete the saved password for '{service}'? This cannot be undone.",
            on_confirm=on_confirm,
            danger=True
        )
    
    # ──────────────────────────────────────────────────────────────────────────
    # SECURITY TAB
    # ──────────────────────────────────────────────────────────────────────────
    def _render_security_tab(self):
        # Header
        header = ctk.CTkFrame(self.content_area, fg_color="transparent")
        header.pack(fill="x", padx=32, pady=(28, 20))
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text="Security Center",
            font=(M3.FONT_DISPLAY[0], 30, "bold"),
            text_color=M3.TEXT_PRIMARY
        ).pack(side="left")
        
        intruder_count = len(list(Path(config.intruder_dir).iterdir()))
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
        
        stats_data = [
            ("🛡️", "Vault Status", "Secured" if self.is_unlocked else "Locked", M3.SUCCESS),
            ("📁", "Protected Files", str(len(list(Path(config.vault_dir).iterdir()))), M3.PRIMARY),
            ("🔑", "Saved Passwords", str(len(self._load_passwords())), M3.SECONDARY),
            ("🚨", "Intrusion Attempts", str(intruder_count), M3.ERROR if intruder_count > 0 else M3.TEXT_TERTIARY)
        ]
        
        for icon, label, value, color in stats_data:
            stat_item = ctk.CTkFrame(stats_inner, fg_color="transparent")
            stat_item.pack(side="left", expand=True)
            
            ctk.CTkLabel(
                stat_item, text=icon,
                font=(M3.FONT_DISPLAY[0], 28),
                anchor="center"
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
        
        intruders = list(Path(config.intruder_dir).iterdir())
        
        if not intruders:
            empty_frame = ctk.CTkFrame(scroll, fg_color="transparent")
            empty_frame.pack(expand=True, pady=50)
            
            ctk.CTkLabel(
                empty_frame, text="✅",
                font=(M3.FONT_DISPLAY[0], 56),
                anchor="center"
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
            for intruder_path in sorted(intruders, key=lambda x: x.stat().st_mtime, reverse=True):
                IntruderCard(
                    scroll,
                    intruder_path,
                    on_view=self._view_intruder,
                    on_delete=self._delete_intruder
                ).pack(fill="x", pady=5, padx=12)
    
    def _view_intruder(self, path: Path) -> None:
        try:
            os.startfile(str(path))
        except Exception as e:
            logger.error(f"Failed to open intruder image: {e}")
            self.show_toast(f"Error opening image: {str(e)}", "error")
    
    def _delete_intruder(self, path: Path) -> None:
        def on_confirm():
            try:
                path.unlink()
                self.show_toast("Intruder log deleted", "success")
                self.set_tab("security")
            except Exception as e:
                logger.error(f"Failed to delete intruder log: {e}")
                self.show_toast(f"Error: {str(e)}", "error")
        
        ConfirmDialog(
            self,
            title="Delete Log?",
            message="Delete this intrusion attempt log?",
            on_confirm=on_confirm,
            danger=False
        )
    
    def _clear_all_intruders(self) -> None:
        def on_confirm():
            try:
                for file in Path(config.intruder_dir).iterdir():
                    file.unlink()
                self.show_toast("All intruder logs cleared", "success")
                self.set_tab("security")
            except Exception as e:
                logger.error(f"Failed to clear intruder logs: {e}")
                self.show_toast(f"Error: {str(e)}", "error")
        
        ConfirmDialog(
            self,
            title="🗑️  Clear All Logs?",
            message="This will permanently delete all intrusion attempt photos. This cannot be undone.",
            on_confirm=on_confirm,
            danger=True
        )


# ══════════════════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point for M3-VAULT"""
    try:
        # Configure CustomTkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create and run application
        app = VaultApp()
        app.mainloop()
        
    except Exception as e:
        logger.critical(f"Application crashed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()