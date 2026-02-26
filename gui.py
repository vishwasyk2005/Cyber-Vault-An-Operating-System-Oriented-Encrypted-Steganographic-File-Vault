import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import threading

from core.encryptor import encrypt_file, decrypt_file
from core.stego import hide_data_in_image, extract_data_from_image
from os_layer.permissions import secure_file

VAULT_DIR = "vaults"
os.makedirs(VAULT_DIR, exist_ok=True)

# Refined color palette
class Theme:
    # Base colors
    BG_PRIMARY = "#09090b"
    BG_SECONDARY = "#18181b"
    BG_TERTIARY = "#27272a"
    BG_ELEVATED = "#1f1f23"

    # Accent colors
    ACCENT_PRIMARY = "#8b5cf6"
    ACCENT_HOVER = "#a78bfa"
    SUCCESS = "#22c55e"
    SUCCESS_HOVER = "#4ade80"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"

    # Text colors
    TEXT_PRIMARY = "#fafafa"
    TEXT_SECONDARY = "#a1a1aa"
    TEXT_MUTED = "#71717a"

    # Border colors
    BORDER = "#27272a"
    BORDER_HOVER = "#3f3f46"
    BORDER_FOCUS = "#8b5cf6"

ctk.set_appearance_mode("dark")


class InputField(ctk.CTkFrame):
    """Refined input field with label"""
    def __init__(self, master, label, placeholder, icon=None, is_password=False,
                 has_browse=False, filetypes=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.filetypes = filetypes
        self.grid_columnconfigure(0, weight=1)

        # Label row
        label_frame = ctk.CTkFrame(self, fg_color="transparent", height=24)
        label_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        label_frame.grid_propagate(False)

        if icon:
            ctk.CTkLabel(
                label_frame,
                text=icon,
                font=ctk.CTkFont(size=14),
                text_color=Theme.TEXT_SECONDARY
            ).pack(side="left")

        ctk.CTkLabel(
            label_frame,
            text=label,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Theme.TEXT_PRIMARY
        ).pack(side="left", padx=(6 if icon else 0, 0))

        # Input row
        input_frame = ctk.CTkFrame(self, fg_color="transparent")
        input_frame.grid(row=1, column=0, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.entry = ctk.CTkEntry(
            input_frame,
            placeholder_text=placeholder,
            height=44,
            corner_radius=8,
            border_width=1,
            border_color=Theme.BORDER,
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_PRIMARY,
            placeholder_text_color=Theme.TEXT_MUTED,
            font=ctk.CTkFont(size=13),
            show="•" if is_password else ""
        )
        self.entry.grid(row=0, column=0, sticky="ew")

        # Focus effects
        self.entry.bind("<FocusIn>", lambda e: self.entry.configure(border_color=Theme.BORDER_FOCUS))
        self.entry.bind("<FocusOut>", lambda e: self.entry.configure(border_color=Theme.BORDER))

        if is_password:
            self._visible = False
            self.toggle_btn = ctk.CTkButton(
                input_frame,
                text="Show",
                width=60,
                height=44,
                corner_radius=8,
                fg_color=Theme.BG_TERTIARY,
                hover_color=Theme.BORDER_HOVER,
                text_color=Theme.TEXT_SECONDARY,
                font=ctk.CTkFont(size=12),
                command=self._toggle_password
            )
            self.toggle_btn.grid(row=0, column=1, padx=(8, 0))

        if has_browse:
            self.browse_btn = ctk.CTkButton(
                input_frame,
                text="Browse",
                width=80,
                height=44,
                corner_radius=8,
                fg_color=Theme.BG_TERTIARY,
                hover_color=Theme.BORDER_HOVER,
                text_color=Theme.TEXT_SECONDARY,
                font=ctk.CTkFont(size=13),
                command=self._browse
            )
            self.browse_btn.grid(row=0, column=1, padx=(8, 0))

    def _toggle_password(self):
        self._visible = not self._visible
        self.entry.configure(show="" if self._visible else "•")
        self.toggle_btn.configure(text="Hide" if self._visible else "Show")

    def _browse(self):
        if self.filetypes:
            path = filedialog.askopenfilename(filetypes=self.filetypes)
        else:
            path = filedialog.askopenfilename()
        if path:
            self.entry.delete(0, "end")
            self.entry.insert(0, path)

    def get(self):
        return self.entry.get().strip()

    def clear(self):
        self.entry.delete(0, "end")


class ActionButton(ctk.CTkButton):
    """Refined action button"""
    def __init__(self, master, variant="primary", **kwargs):
        colors = {
            "primary": (Theme.ACCENT_PRIMARY, Theme.ACCENT_HOVER),
            "success": (Theme.SUCCESS, Theme.SUCCESS_HOVER),
        }
        fg, hover = colors.get(variant, colors["primary"])

        super().__init__(
            master,
            height=48,
            corner_radius=8,
            fg_color=fg,
            hover_color=hover,
            text_color=Theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=14, weight="bold"),
            **kwargs
        )


class Card(ctk.CTkFrame):
    """Refined card container"""
    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=Theme.BG_ELEVATED,
            corner_radius=12,
            border_width=1,
            border_color=Theme.BORDER,
            **kwargs
        )


class CyberVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberVault")
        self.geometry("540x720")
        self.minsize(480, 680)
        self.configure(fg_color=Theme.BG_PRIMARY)

        # Main container with consistent padding
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=32, pady=32)

        self._build_header()
        self._build_navigation()
        self._build_content()

    def _build_header(self):
        """App header with logo and title"""
        header = ctk.CTkFrame(self.container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 24))

        # Logo
        logo_bg = ctk.CTkFrame(
            header,
            width=56,
            height=56,
            corner_radius=12,
            fg_color=Theme.ACCENT_PRIMARY
        )
        logo_bg.pack()
        logo_bg.pack_propagate(False)

        ctk.CTkLabel(
            logo_bg,
            text="🔐",
            font=ctk.CTkFont(size=24)
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ctk.CTkLabel(
            header,
            text="CyberVault",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Theme.TEXT_PRIMARY
        ).pack(pady=(12, 2))

        ctk.CTkLabel(
            header,
            text="Secure steganography encryption",
            font=ctk.CTkFont(size=13),
            text_color=Theme.TEXT_MUTED
        ).pack()

    def _build_navigation(self):
        """Tab navigation"""
        nav = Card(self.container)
        nav.pack(fill="x", pady=(0, 20))

        nav_inner = ctk.CTkFrame(nav, fg_color="transparent")
        nav_inner.pack(fill="x", padx=4, pady=4)
        nav_inner.grid_columnconfigure((0, 1), weight=1)

        self.current_tab = "lock"

        self.lock_tab = ctk.CTkButton(
            nav_inner,
            text="Lock",
            height=40,
            corner_radius=8,
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_HOVER,
            text_color=Theme.TEXT_PRIMARY,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._switch_tab("lock")
        )
        self.lock_tab.grid(row=0, column=0, sticky="ew", padx=(0, 2))

        self.unlock_tab = ctk.CTkButton(
            nav_inner,
            text="Unlock",
            height=40,
            corner_radius=8,
            fg_color="transparent",
            hover_color=Theme.BG_TERTIARY,
            text_color=Theme.TEXT_SECONDARY,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._switch_tab("unlock")
        )
        self.unlock_tab.grid(row=0, column=1, sticky="ew", padx=(2, 0))

    def _build_content(self):
        """Main content area"""
        self.content = ctk.CTkFrame(self.container, fg_color="transparent")
        self.content.pack(fill="both", expand=True)

        self._build_lock_view()
        self._build_unlock_view()

        self.lock_view.pack(fill="both", expand=True)

    def _build_lock_view(self):
        """Lock tab content"""
        self.lock_view = ctk.CTkFrame(self.content, fg_color="transparent")

        # Form card
        form = Card(self.lock_view)
        form.pack(fill="x")

        form_inner = ctk.CTkFrame(form, fg_color="transparent")
        form_inner.pack(fill="x", padx=20, pady=20)

        # Secret file input
        self.secret_input = InputField(
            form_inner,
            label="Secret File",
            placeholder="Select file to encrypt and hide...",
            icon="📄",
            has_browse=True
        )
        self.secret_input.pack(fill="x", pady=(0, 16))

        # Cover image input
        self.cover_input = InputField(
            form_inner,
            label="Cover Image",
            placeholder="Select PNG image as cover...",
            icon="🖼",
            has_browse=True,
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        self.cover_input.pack(fill="x", pady=(0, 16))

        # Password input
        self.lock_password_input = InputField(
            form_inner,
            label="Password",
            placeholder="Enter encryption password...",
            icon="🔑",
            is_password=True
        )
        self.lock_password_input.pack(fill="x")

        # Options
        options = ctk.CTkFrame(self.lock_view, fg_color="transparent")
        options.pack(fill="x", pady=(16, 0))

        self.delete_original = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            options,
            text="Delete original file after locking",
            variable=self.delete_original,
            font=ctk.CTkFont(size=13),
            text_color=Theme.TEXT_SECONDARY,
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_HOVER,
            border_color=Theme.BORDER,
            checkmark_color=Theme.TEXT_PRIMARY
        ).pack(anchor="w")

        # Lock button
        self.lock_btn = ActionButton(
            self.lock_view,
            text="Lock File",
            variant="primary",
            command=self._execute_lock
        )
        self.lock_btn.pack(fill="x", pady=(20, 0))

    def _build_unlock_view(self):
        """Unlock tab content"""
        self.unlock_view = ctk.CTkFrame(self.content, fg_color="transparent")

        # Form card
        form = Card(self.unlock_view)
        form.pack(fill="x")

        form_inner = ctk.CTkFrame(form, fg_color="transparent")
        form_inner.pack(fill="x", padx=20, pady=20)

        # Vault image input
        self.vault_input = InputField(
            form_inner,
            label="Vault Image",
            placeholder="Select vault image from vaults folder...",
            icon="🔒",
            has_browse=True,
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        self.vault_input.pack(fill="x", pady=(0, 16))

        # Password input
        self.unlock_password_input = InputField(
            form_inner,
            label="Password",
            placeholder="Enter decryption password...",
            icon="🔑",
            is_password=True
        )
        self.unlock_password_input.pack(fill="x")

        # Unlock button
        self.unlock_btn = ActionButton(
            self.unlock_view,
            text="Unlock File",
            variant="success",
            command=self._execute_unlock
        )
        self.unlock_btn.pack(fill="x", pady=(20, 0))

        # Info card
        info = Card(self.unlock_view)
        info.pack(fill="x", pady=(20, 0))

        info_inner = ctk.CTkFrame(info, fg_color="transparent")
        info_inner.pack(fill="x", padx=16, pady=14)

        ctk.CTkLabel(
            info_inner,
            text="ℹ  Important",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=Theme.ACCENT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            info_inner,
            text="Select the vault image from the 'vaults' folder, not the original cover image.",
            font=ctk.CTkFont(size=12),
            text_color=Theme.TEXT_SECONDARY,
            wraplength=400,
            justify="left"
        ).pack(anchor="w", pady=(4, 0))

    def _switch_tab(self, tab):
        if tab == self.current_tab:
            return

        self.current_tab = tab

        if tab == "lock":
            self.lock_tab.configure(
                fg_color=Theme.ACCENT_PRIMARY,
                hover_color=Theme.ACCENT_HOVER,
                text_color=Theme.TEXT_PRIMARY
            )
            self.unlock_tab.configure(
                fg_color="transparent",
                hover_color=Theme.BG_TERTIARY,
                text_color=Theme.TEXT_SECONDARY
            )
            self.unlock_view.pack_forget()
            self.lock_view.pack(fill="both", expand=True)
        else:
            self.unlock_tab.configure(
                fg_color=Theme.SUCCESS,
                hover_color=Theme.SUCCESS_HOVER,
                text_color=Theme.TEXT_PRIMARY
            )
            self.lock_tab.configure(
                fg_color="transparent",
                hover_color=Theme.BG_TERTIARY,
                text_color=Theme.TEXT_SECONDARY
            )
            self.lock_view.pack_forget()
            self.unlock_view.pack(fill="both", expand=True)

    def _execute_lock(self):
        secret = self.secret_input.get()
        cover = self.cover_input.get()
        password = self.lock_password_input.get()

        # Validation
        if not secret:
            messagebox.showerror("Error", "Please select a secret file")
            return
        if not cover:
            messagebox.showerror("Error", "Please select a cover image")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        if not os.path.exists(secret):
            messagebox.showerror("Error", "Secret file not found")
            return
        if not os.path.exists(cover):
            messagebox.showerror("Error", "Cover image not found")
            return

        self.lock_btn.configure(state="disabled", text="Encrypting...")

        def task():
            try:
                encrypted = encrypt_file(secret, password.encode())

                name = os.path.splitext(os.path.basename(secret))[0]
                vault_path = os.path.join(VAULT_DIR, f"{name}_vault.png")
                counter = 1
                while os.path.exists(vault_path):
                    vault_path = os.path.join(VAULT_DIR, f"{name}_vault_{counter}.png")
                    counter += 1

                hide_data_in_image(cover, encrypted, vault_path)
                secure_file(vault_path)

                if self.delete_original.get():
                    os.remove(secret)

                self.after(0, lambda p=vault_path: self._on_lock_success(p))
            except Exception as e:
                self.after(0, lambda err=str(e): self._on_lock_error(err))

        threading.Thread(target=task, daemon=True).start()

    def _on_lock_success(self, vault_path):
        self.lock_btn.configure(state="normal", text="Lock File")
        self.secret_input.clear()
        self.cover_input.clear()
        self.lock_password_input.clear()
        messagebox.showinfo("Success", f"File encrypted and hidden.\n\nVault saved to:\n{vault_path}")

    def _on_lock_error(self, error):
        self.lock_btn.configure(state="normal", text="Lock File")
        messagebox.showerror("Error", f"Failed to lock file:\n{error}")

    def _execute_unlock(self):
        vault = self.vault_input.get()
        password = self.unlock_password_input.get()

        # Validation
        if not vault:
            messagebox.showerror("Error", "Please select a vault image")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        if not os.path.exists(vault):
            messagebox.showerror("Error", "Vault image not found")
            return

        self.unlock_btn.configure(state="disabled", text="Decrypting...")

        def task():
            try:
                data = extract_data_from_image(vault)
                output = decrypt_file(data, password.encode())
                self.after(0, lambda f=output: self._on_unlock_success(f))
            except ValueError:
                self.after(0, lambda: self._on_unlock_error("No hidden data found in this image"))
            except Exception as e:
                err = str(e)
                if "tag" in err.lower() or "mac" in err.lower():
                    err = "Incorrect password or corrupted data"
                self.after(0, lambda msg=err: self._on_unlock_error(msg))

        threading.Thread(target=task, daemon=True).start()

    def _on_unlock_success(self, output_file):
        self.unlock_btn.configure(state="normal", text="Unlock File")
        self.vault_input.clear()
        self.unlock_password_input.clear()
        messagebox.showinfo("Success", f"File recovered.\n\nSaved as:\n{output_file}")

    def _on_unlock_error(self, error):
        self.unlock_btn.configure(state="normal", text="Unlock File")
        messagebox.showerror("Error", f"Failed to unlock:\n{error}")


def main():
    app = CyberVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
