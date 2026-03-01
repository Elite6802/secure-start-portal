Secure Start / Aegis Backend (Django + DRF)

Quick start (local):
1. Create a virtual environment and install requirements.
2. Copy `.env.example` to `.env` and update values as needed.
3. Run migrations and create a superuser.
4. Start the server.

Example commands (Windows PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Docker:
```bash
docker compose up --build
```
