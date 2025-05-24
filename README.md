# Backend for Pfsense configuration

## Installation

1. Clone the repository:

2. Create a virtual environment (optional but recommended):

* For Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

* For Windows:
```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables if using wan interface:
   - Create a `.env` file in the root directory and add the following variables:
     ```
     PFSENSE_HOST=wan-ip-address
     ```
