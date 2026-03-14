export $(cat .env | xargs) && python3 dashboard/app.py
