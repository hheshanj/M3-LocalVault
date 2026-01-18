# 🔐 M3-VAULT | Biometric & PIN Secure Storage

**M3-VAULT** is a high-security local storage solution designed with a sleek **Material You (M3)** interface. It combines cryptographically secure encryption with **Face ID** biometric authentication to keep your sensitive files and passwords on lockdown.

---

## 🚀 Key Features

* **Biometric Authentication:** Powered by `DeepFace`. The vault only unlocks when it verifies your face against the registered master profile.
* **Military-Grade Encryption:** Uses **AES-256 (Fernet)** to encrypt files. Your data is unreadable to anyone—even if they have access to your hard drive.
* **Intruder Logging:** Automatically snaps a photo of anyone who fails the login process and stores it in a dedicated "Intruders" gallery.
* **Password Manager:** Built-in vault to store and generate complex passwords with a secure auto-clear clipboard feature.
* **Secure Shredding:** Implements multi-pass random data overwriting (Gutmann-style) to ensure "deleted" files are unrecoverable.
* **Inactivity Auto-Lock:** Automatically locks the session after 5 minutes (configurable) to prevent unauthorized access while you're away.

---


## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **UI Framework:** `customtkinter` (Material Design 3 Components)
* **Computer Vision:** `OpenCV`, `DeepFace`
* **Cryptography:** `cryptography.py`
* **Database:** JSON-based encrypted flat files

---

## 📦 Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/hheshanj/M3-LocalVault
    ```
    ```bash
    cd M3-LocalVault
    ```

2.  **Install Dependencies:**
    *Note: TensorFlow (via DeepFace) is required for the biometric features.*
    ```bash
    pip install customtkinter opencv-python deepface cryptography pillow
    ```

3.  **Launch the App:**
    ```bash
    python main.py
    ```

---

> I hate python and definitely doesn't use arch

---
*Disclaimer: This project is for educational purposes and personal use. Always keep a backup of your master salt and key files in a separate secure location.*
