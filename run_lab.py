"""Run only in a local isolated environment; never deploy this lab."""
import uvicorn
from lab.main import create_lab

if __name__ == '__main__':
    uvicorn.run(create_lab(), host='127.0.0.1', port=5001, server_header=False)
