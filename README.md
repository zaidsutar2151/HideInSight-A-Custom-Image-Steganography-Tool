# HideInSight – A Custom Image Steganography Tool

**HideInSight** is a Python-based GUI application that securely hides and retrieves secret messages inside image files using Least Significant Bit (LSB) steganography and optional XOR encryption. It provides a clean interface to encrypt, embed, extract, and view hidden messages without altering the visible appearance of the image.

---

## 🔐 Features

- Hide text messages inside `.png`, `.jpg`, or `.bmp` images
- Secure XOR-based message encryption before embedding
- Decode hidden messages only using your custom tool
- GUI built with Tkinter for ease of use
- Real-time image preview and character count
- Simple, clean, and efficient user interface

---

## 🖼️ How It Works

1. **Select an image**
2. **Enter a message**
3. **Click "Hide Message"** – the message is encrypted and embedded into the image using LSB in the red channel.
4. **Click "Extract Message"** – retrieves and decrypts the message from a modified image.

---

## 💻 Technologies Used

- **Python 3**
- **Tkinter** – GUI development
- **Pillow (PIL)** – Image processing
- **Custom XOR Encryption** – Simple but effective encoding scheme

---

## 📦 Installation

1. Clone this repository or download the `.py` file
2. Install dependencies:
   ```bash
   pip install pillow
   ```
3. Run the application:
   ```bash
   python main.py
   ```

---

## 📁 Supported Image Formats

- PNG (`.png`)
- JPEG (`.jpg`, `.jpeg`)
- BMP (`.bmp`)

---

## ⚠️ Disclaimer

This tool is built for educational and experimental use. It does not use advanced encryption techniques, so it should not be used for hiding highly sensitive or confidential information.

---

## 🧑‍💻 Author

Developed by **Md Zaid Sutar**  
Feel free to contribute or suggest improvements!
