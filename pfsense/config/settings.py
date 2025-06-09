import os

from dotenv import load_dotenv

if os.path.exists(".env"):
    load_dotenv()

CONFIG_DIR = os.environ.get("CONFIG_DIR", "/conf/config.xml")
BACKUP_CONFIG_DIR = os.environ.get("BACKUP_CONFIG_DIR", "/conf/config.xml.bak")

PFSENSE_USERNAME = os.environ.get("PFSENSE_USERNAME", "admin")
PFSENSE_PASSWORD = os.environ.get("PFSENSE_PASSWORD", "pfsense")
PFSENSE_HOST = os.environ.get("PFSENSE_HOST", "pfsense.home.arpa")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
