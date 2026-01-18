import os, cv2, time, json, string, random, shutil
import threading
from pathlib import Path
from deepface import DeepFace
from cryptography.fernet import Fernet
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image

# --- 1. SETTINGS & DESIGN SYSTEM ---
VAULT_DIR = Path("vault_storage")
INTRUDER_DIR = Path("intruders")
[d.mkdir(exist_ok=True) for d in [VAULT_DIR, INTRUDER_DIR]]

MASTER_FACE = "master_face.jpg"
KEY_FILE = "master.key"

M3 = {
    "bg": "#1A1C1E",
    "surface": "#2F3033",
    "primary": "#D0E4FF",
    "on_primary": "#00315B",
    "secondary_container": "#43474E",
    "error": "#FFB4AB",
    "on_error": "#690005",
    "text": "#E2E2E6"
}

# --- 2. ENCRYPTION ENGINE ---
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f: f.write(key)
else:
    with open(KEY_FILE, "rb") as f: key = f.read()
cipher = Fernet(key)

# --- 3. CORE LOGIC ---
def shred_file(path):
    size = os.path.getsize(path)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    os.remove(path)


# Disable those annoying oneDNN messages
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'


# --- 4. MAIN APPLICATION ---
class FortressApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("System Service") # Stealth title
        self.geometry("1100x700")
        self.configure(fg_color=M3["bg"])
        
        self.is_unlocked = False
        self.active_tab = "files"
        self.show_login()

    def show_login(self):
        self.clear_ui()
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(expand=True)
        
        ctk.CTkLabel(frame, text="M3-Vault", font=("Inter", 32, "bold"), text_color=M3["primary"]).pack(pady=20)
        self.auth_btn = ctk.CTkButton(frame, text="Unlock with Face ID", corner_radius=28, 
                                     fg_color=M3["primary"], text_color=M3["on_primary"],
                                     height=56, width=280, font=("Inter", 16, "bold"),
                                     command=self.run_auth)
        self.auth_btn.pack(pady=10)

    def run_auth(self):
        self.auth_btn.configure(text="Scanning Face...")
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()
        
        if ret:
            img_p = "temp_auth.jpg"
            cv2.imwrite(img_p, frame)
            try:
                res = DeepFace.verify(img_p, MASTER_FACE, enforce_detection=True)
                if res['verified']:
                    self.is_unlocked = True
                    self.show_dashboard()
                else:
                    # Feature: Intruder Selfie
                    os.rename(img_p, INTRUDER_DIR / f"intruder_{int(time.time())}.jpg")
                    messagebox.showerror("Security", "Unauthorized! Intruder photo logged.")
            except:
                messagebox.showwarning("Error", "No face detected. Look at the camera, bro.")
            if os.path.exists(img_p): os.remove(img_p)

    def show_dashboard(self):
        self.clear_ui()
        
        # Navigation Rail (Sidebar) remains the same
        self.rail = ctk.CTkFrame(self, width=100, fg_color="transparent")
        self.rail.pack(side="left", fill="y", padx=15, pady=20)
        self.add_nav("📁", lambda: self.set_tab("files"))
        self.add_nav("🔑", lambda: self.set_tab("passwords"))
        
        # Main Container
        self.container = ctk.CTkFrame(self, corner_radius=28, fg_color=M3["secondary_container"])
        self.container.pack(side="right", expand=True, fill="both", padx=20, pady=20)

        # --- PREVIEW SYSTEM START ---
        # Create a Left Frame for the file list
        self.list_view = ctk.CTkFrame(self.container, fg_color="transparent")
        self.list_view.pack(side="left", expand=True, fill="both", padx=(10, 0))

        # Create a Right Frame for the preview
        self.preview_pane = ctk.CTkFrame(self.container, width=350, corner_radius=24, fg_color=M3["bg"])
        self.preview_pane.pack(side="right", fill="y", padx=15, pady=15)
        
        ctk.CTkLabel(self.preview_pane, text="FILE PREVIEW", font=("Inter", 12, "bold"), text_color=M3["primary"]).pack(pady=15)
        
        # This label will hold either text or an image
        self.preview_display = ctk.CTkLabel(self.preview_pane, text="Select a file to preview", wraplength=300)
        self.preview_display.pack(expand=True, padx=20)
        # --- PREVIEW SYSTEM END ---

        self.set_tab("files")

    def add_nav(self, icon, cmd):
        btn = ctk.CTkButton(self.rail, text=icon, width=60, height=60, corner_radius=18,
                            fg_color=M3["surface"], font=("Inter", 24), command=cmd)
        btn.pack(pady=10)

    def set_tab(self, tab):
        for w in self.container.winfo_children(): w.destroy()
        if tab == "files": self.render_files()
        elif tab == "passwords": self.render_passwords()
        elif tab == "intruders": self.render_intruders()

    # --- TAB: FILES ---
    def render_files(self):
        # Pack everything into self.list_view instead of self.container
        for w in self.list_view.winfo_children(): w.destroy()
        
        header = ctk.CTkFrame(self.list_view, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(header, text="Encrypted Locker", font=("Inter", 24, "bold")).pack(side="left")
        ctk.CTkButton(header, text="+ Add", width=80, command=self.upload_file).pack(side="right")

        scroll = ctk.CTkScrollableFrame(self.list_view, fg_color="transparent")
        scroll.pack(expand=True, fill="both")

        for f_p in VAULT_DIR.iterdir():
            card = ctk.CTkFrame(scroll, fg_color=M3["bg"], corner_radius=16)
            card.pack(fill="x", pady=5)
            
            # Clickable name for Preview
            name_btn = ctk.CTkButton(card, text=f"📄 {f_p.name}", fg_color="transparent", 
                                    anchor="w", hover_color=M3["surface"],
                                    command=lambda p=f_p: self.show_preview(p))
            name_btn.pack(side="left", fill="x", expand=True, padx=10, pady=10)
            
            ctk.CTkButton(card, text="Open", width=60, command=lambda p=f_p: self.open_file(p)).pack(side="right", padx=5)
    
    def show_preview(self, path):
        try:
            with open(path, "rb") as f:
                decrypted_data = cipher.decrypt(f.read())
            
            ext = path.suffix.lower()

            # For Images
            if ext in ['.jpg', '.jpeg', '.png', '.bmp']:
                from io import BytesIO
                img_data = BytesIO(decrypted_data)
                img = Image.open(img_data)
                
                # Dynamic scaling to fit the pane
                ratio = min(300/img.width, 400/img.height)
                new_size = (int(img.width * ratio), int(img.height * ratio))
                
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=new_size)
                self.preview_display.configure(image=ctk_img, text="")
            
            # For Text
            elif ext in ['.txt', '.py', '.json', '.dat']:
                text_content = decrypted_data[:1000].decode('utf-8', errors='ignore')
                self.preview_display.configure(image="", text=text_content, font=("Courier New", 11), justify="left")
            
            else:
                self.preview_display.configure(image="", text=f"No preview for {ext}\nOpen to view full file.")
                
        except Exception as e:
            self.preview_display.configure(text=f"Decryption Error: {e}")

    def upload_file(self):
        p = filedialog.askopenfilename()
        if p:
            with open(p, "rb") as f: data = f.read()
            with open(VAULT_DIR / os.path.basename(p), "wb") as f: f.write(cipher.encrypt(data))
            self.render_files()

    def open_file(self, path):
        with open(path, "rb") as f: data = f.read()
        tmp = f"VIEW_{path.name}"
        with open(tmp, "wb") as f: f.write(cipher.decrypt(data))
        os.startfile(tmp)

    # --- TAB: PASSWORDS ---
    def render_passwords(self):
        ctk.CTkLabel(self.container, text="Password Manager", font=("Inter", 28, "bold")).pack(anchor="w", padx=30, pady=30)
        
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.pack(fill="x", padx=30)
        
        site_e = ctk.CTkEntry(f, placeholder_text="App Name", corner_radius=15, height=45)
        site_e.pack(side="left", expand=True, fill="x", padx=5)
        pass_e = ctk.CTkEntry(f, placeholder_text="Password", corner_radius=15, height=45, show="*")
        pass_e.pack(side="left", expand=True, fill="x", padx=5)
        
        def save_p():
            db = "passwords.dat"
            data = {}
            if os.path.exists(db):
                with open(db, "rb") as file: data = json.loads(cipher.decrypt(file.read()))
            data[site_e.get()] = pass_e.get()
            with open(db, "wb") as file: file.write(cipher.encrypt(json.dumps(data).encode()))
            self.render_passwords()

        ctk.CTkButton(f, text="Save", corner_radius=15, width=100, command=save_p).pack(side="left", padx=5)

    # --- TAB: INTRUDER LOGS ---
    def render_intruders(self):
        ctk.CTkLabel(self.container, text="Security Logs", font=("Inter", 28, "bold")).pack(anchor="w", padx=30, pady=30)
        scroll = ctk.CTkScrollableFrame(self.container, fg_color="transparent")
        scroll.pack(expand=True, fill="both", padx=20)
        
        for i_p in INTRUDER_DIR.iterdir():
            card = ctk.CTkFrame(scroll, fg_color=M3["bg"], corner_radius=16)
            card.pack(fill="x", pady=5)
            ctk.CTkLabel(card, text=f"🚨 Attempted Access: {i_p.name}").pack(side="left", padx=20, pady=15)
            ctk.CTkButton(card, text="View Pic", width=80, command=lambda p=i_p: os.startfile(p)).pack(side="right", padx=10)

    def clear_ui(self):
        for w in self.winfo_children(): w.destroy()

if __name__ == "__main__":
    app = FortressApp()
    app.mainloop()