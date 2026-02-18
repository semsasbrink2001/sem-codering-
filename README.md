# sem-codering-

Flask webapp met:

- Registreren, inloggen en uitloggen
- Persoonlijk dashboard voor ingelogde gebruikers
- Admin-beheerpanel om alle gebruikers te bekijken en aan te passen (rol, activatie, wachtwoord reset, verwijderen, toevoegen)

## Snel starten

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

De app draait dan op `http://localhost:5000`.

## Standaard admin-account

Bij de eerste start wordt automatisch een admin aangemaakt:

- gebruikersnaam: `admin`
- wachtwoord: `admin123`

Je kunt dit aanpassen met environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SECRET_KEY`
