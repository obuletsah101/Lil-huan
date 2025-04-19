# Lil-huan/
├── config/
│   ├── config_template.json
│   └── .env.example
├── utils/
│   ├── encryption.py
│   └── config_loader.py
{
  "binance": {
    "apiKey": "your-binance-api-key",
    "secret": "your-binance-secret"
  },
  "kraken": {
    "apiKey": "your-kraken-api-key",
    "secret": "your-kraken-secret"
  },
  "kucoin": {
    "apiKey": "your-kucoin-api-key",
    "secret": "your-kucoin-secret"
  },
  "coinbase": {
    "apiKey": "your-coinbase-api-key",
    "secret": "your-coinbase-secret"
  },
  "bybit": {
    "apiKey": "your-bybit-api-key",
    "secret": "your-bybit-secret"
  },
  "bitget": {
    "apiKey": "your-bitget-api-key",
    "secret": "your-bitget-secret"
  },
  "cryptocom": {
    "apiKey": "your-crypto-api-key",
    "secret": "your-crypto-secret"
  }
}
BINANCE_API_KEY=your-binance-api-key
BINANCE_SECRET=your-binance-secret
# Repeat for all other exchanges...
from cryptography.fernet import Fernet
import base64
import os
from hashlib import pbkdf2_hmac

def derive_key(password: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32))

def encrypt_file(input_path: str, output_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    with open(output_path, 'wb') as f:
        f.write(salt + encrypted)

def decrypt_file(input_path: str, password: str) -> bytes:
    with open(input_path, 'rb') as f:
        content = f.read()
    salt, encrypted = content[:16], content[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted)
    import os
import json
from dotenv import load_dotenv
from utils.encryption import decrypt_file

def load_config_from_env():
    load_dotenv()
    keys = {}
    for ex in ['binance', 'kraken', 'kucoin', 'coinbase', 'bybit', 'bitget', 'cryptocom']:
        keys[ex] = {
            "apiKey": os.getenv(f"{ex.upper()}_API_KEY"),
            "secret": os.getenv(f"{ex.upper()}_SECRET")
        }
    return keys

def load_config_from_encrypted(path='config/config.json.enc', password=''):
    decrypted_data = decrypt_file(path, password)
    return json.loads(decrypted_data.decode())
