import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = ROOT / 'backend'

if not BACKEND_ROOT.exists():
    raise SystemExit(
        'Backend directory not found. Run this script from the full_package folder and ensure backend/ exists.'
    )

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BACKEND_ROOT))

API_HOST = '127.0.0.1'
API_PORT = 8080

if __name__ == '__main__':
    try:
        import uvicorn
    except ImportError:
        raise SystemExit(
            'uvicorn is not installed. Install server deps with: pip install -r backend/requirements.txt'
        )

    print(f'Starting PhishGuard backend on http://{API_HOST}:{API_PORT}')
    uvicorn.run('backend.main:app', host=API_HOST, port=API_PORT, reload=False)
