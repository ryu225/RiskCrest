"""Start the secure application at https://127.0.0.1:5443.

Generate a development certificate using python scripts/create_dev_cert.py.
"""
import uvicorn
from app.main import ROOT, create_app

if __name__ == '__main__':
    cert = ROOT / 'instance' / 'certs' / 'localhost.crt'
    key = ROOT / 'instance' / 'certs' / 'localhost.key'
    if not cert.exists() or not key.exists():
        raise SystemExit('Missing development certificate. Run python scripts/create_dev_cert.py')
    uvicorn.run(create_app(), host='127.0.0.1', port=5443,
                ssl_certfile=str(cert), ssl_keyfile=str(key), server_header=False)
