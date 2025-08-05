import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os

def encrypt_message(message, key=23):
    return ''.join([chr(ord(c) ^ key) for c in message])

def decrypt_message(encrypted_message, key=23):
    return ''.join([chr(ord(c) ^ key) for c in encrypted_message])

def message_to_bits(message):
    return ''.join([format(ord(char), '08b') for char in message])

def bits_to_message(bits):
    all_bytes = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    message = ""
    for byte in all_bytes:
        char = chr(int(byte, 2))
        if char == chr(0):
            break
        message += char
    return message

def hide_data_in_image(image_path, output_path, message, key=23):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    encrypted_message = encrypt_message(message, key) + chr(0)
    binary_message = message_to_bits(encrypted_message)
    width, height = img.size
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx < len(binary_message):
                r, g, b = pixels[x, y]
                new_r = (r & ~1) | int(binary_message[idx])
                pixels[x, y] = (new_r, g, b)
                idx += 1
            else:
                break
        if idx >= len(binary_message):
            break
    img.save(output_path)

def extract_data_from_image(image_path, key=23):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()
    width, height = img.size
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
    message = bits_to_message(binary_data)
    return decrypt_message(message, key)

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Tool")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.root.configure(bg='#f0f0f0')

        style = ttk.Style()
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Heading.TLabel', font=('Arial', 11, 'bold'), background='#f0f0f0')
        style.configure('Custom.TButton', font=('Arial', 10))
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))

        self.image_path = ""
        self.output_path = "output_hidden.png"
        self.tk_image = None

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text="Image Steganography Tool", style='Title.TLabel')
        title_label.pack(pady=(0, 20))

        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(content_frame, padding="10")
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        right_frame = ttk.Frame(content_frame, padding="10")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        img_section = ttk.LabelFrame(left_frame, text="Image Selection", padding="10")
        img_section.pack(fill=tk.X, pady=(0, 15))

        self.image_path_var = tk.StringVar()
        self.image_path_var.set("No image selected")

        path_label = ttk.Label(img_section, textvariable=self.image_path_var, foreground='#666666', font=('Arial', 9))
        path_label.pack(anchor=tk.W, pady=(0, 10))

        select_btn = ttk.Button(img_section, text="📁 Select Image", command=self.select_image, style='Custom.TButton')
        select_btn.pack(fill=tk.X)

        msg_section = ttk.LabelFrame(left_frame, text="Message", padding="10")
        msg_section.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(msg_section, text="Enter message to hide:", style='Heading.TLabel').pack(anchor=tk.W, pady=(0, 5))

        text_frame = ttk.Frame(msg_section)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.message_text = tk.Text(text_frame, height=6, width=35, font=('Arial', 10), wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.message_text.yview)
        self.message_text.configure(yscrollcommand=scrollbar.set)

        self.message_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.char_count_var = tk.StringVar()
        self.char_count_var.set("Characters: 0")
        char_count_label = ttk.Label(msg_section, textvariable=self.char_count_var, font=('Arial', 8), foreground='#666666')
        char_count_label.pack(anchor=tk.E, pady=(5, 0))

        self.message_text.bind('<KeyRelease>', self.update_char_count)

        action_section = ttk.LabelFrame(left_frame, text="Actions", padding="10")
        action_section.pack(fill=tk.X, pady=(0, 15))

        hide_btn = ttk.Button(action_section, text="🔒 Hide Message", command=self.hide_message, style='Action.TButton')
        hide_btn.pack(fill=tk.X, pady=(0, 10))

        extract_btn = ttk.Button(action_section, text="🔓 Extract Message", command=self.extract_message, style='Action.TButton')
        extract_btn.pack(fill=tk.X)

        status_section = ttk.LabelFrame(left_frame, text="Status", padding="10")
        status_section.pack(fill=tk.X)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(status_section, textvariable=self.status_var, font=('Arial', 9), foreground='#2e7d32')
        status_label.pack(anchor=tk.W)

        preview_section = ttk.LabelFrame(right_frame, text="Image Preview", padding="10")
        preview_section.pack(fill=tk.BOTH, expand=True)

        self.image_container = ttk.Frame(preview_section, relief=tk.SOLID, borderwidth=1, padding="5")
        self.image_container.pack(fill=tk.BOTH, expand=True)

        self.image_label = ttk.Label(self.image_container, text="No image selected", foreground='#999999', font=('Arial', 12))
        self.image_label.pack(expand=True)

        self.image_info_var = tk.StringVar()
        self.image_info_var.set("")
        info_label = ttk.Label(preview_section, textvariable=self.image_info_var, font=('Arial', 8), foreground='#666666')
        info_label.pack(pady=(10, 0))

    def update_char_count(self, event=None):
        count = len(self.message_text.get("1.0", tk.END).strip())
        self.char_count_var.set(f"Characters: {count}")

    def select_image(self):
        self.image_path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp"), ("PNG Files", "*.png"), ("JPEG Files", "*.jpg *.jpeg"), ("BMP Files", "*.bmp")]
        )

        if self.image_path:
            filename = os.path.basename(self.image_path)
            if len(filename) > 30:
                filename = filename[:27] + "..."
            self.image_path_var.set(filename)

            try:
                img = Image.open(self.image_path)
                width, height = img.size
                self.image_info_var.set(f"Dimensions: {width}x{height} pixels")
                img.thumbnail((350, 350))
                self.tk_image = ImageTk.PhotoImage(img)
                self.image_label.config(image=self.tk_image, text="")
                self.status_var.set("Image loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")
                self.status_var.set("Error loading image")

    def hide_message(self):
        message = self.message_text.get("1.0", tk.END).strip()

        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return

        if not message:
            messagebox.showerror("Error", "Please enter a message to hide!")
            return

        try:
            self.status_var.set("Hiding message...")
            self.root.update()

            output_path = filedialog.asksaveasfilename(
                title="Save Hidden Message Image As",
                defaultextension=".png",
                filetypes=[("PNG Files", "*.png"), ("BMP Files", "*.bmp")]
            )

            if not output_path:
                self.status_var.set("Operation cancelled")
                return

            hide_data_in_image(self.image_path, output_path, message)

            self.status_var.set("Message hidden successfully!")
            messagebox.showinfo("Success", f"Message hidden successfully!\nSaved as: {os.path.basename(output_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide message: {str(e)}")
            self.status_var.set("Error hiding message")

    def extract_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return

        try:
            self.status_var.set("Extracting message...")
            self.root.update()

            extracted = extract_data_from_image(self.image_path)

            if extracted.strip():
                self.show_extracted_message(extracted)
                self.status_var.set("Message extracted successfully!")
            else:
                messagebox.showinfo("No Message", "No hidden message found in this image.")
                self.status_var.set("No message found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract message: {str(e)}")
            self.status_var.set("Error extracting message")

    def show_extracted_message(self, message):
        extract_window = tk.Toplevel(self.root)
        extract_window.title("Extracted Message")
        extract_window.geometry("500x400")
        extract_window.resizable(True, True)
        extract_window.configure(bg='#f0f0f0')

        extract_window.transient(self.root)
        extract_window.grab_set()

        frame = ttk.Frame(extract_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Extracted Message:", style='Heading.TLabel').pack(anchor=tk.W, pady=(0, 10))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(text_frame, font=('Arial', 10), wrap=tk.WORD, relief=tk.SOLID, borderwidth=1, state=tk.NORMAL)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget.insert("1.0", message)
        text_widget.configure(state=tk.DISABLED)

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        def copy_message():
            extract_window.clipboard_clear()
            extract_window.clipboard_append(message)
            copy_btn.config(text="✓ Copied!")
            extract_window.after(2000, lambda: copy_btn.config(text="📋 Copy"))

        copy_btn = ttk.Button(button_frame, text="📋 Copy", command=copy_message)
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(button_frame, text="Close", command=extract_window.destroy).pack(side=tk.RIGHT)

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
