# Flask Steganography App

- Encrypts payload using AES-GCM (authenticated)
- Compresses payload with gzip before encryption
- Embeds encrypted payload into a PNG using LSB steganography
- Allows encoding and decoding via a simple web UI
- Saves resulting stego files in static/encoded/

Usage (local):
1. python3 -m venv venv && source venv/bin/activate
2. pip install -r requirements.txt
3. python app.py
4. Open http://127.0.0.1:5000

Important note for WhatsApp sharing: ALWAYS send the generated PNG as a Document (not Photo) to avoid recompression which destroys LSB data.
