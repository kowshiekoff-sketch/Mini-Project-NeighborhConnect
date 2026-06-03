# LocalConnect - Neighborhood Service Portal

LocalConnect is a Flask mini-project for finding, booking, reviewing, and managing trusted neighborhood service providers. It does not use the Anthropic API or any paid AI API. The recommendation feature is rule-based, using ratings, booking history, availability, emergency support, and category matching.

## Features

- Customer, service provider, and admin login flows
- Provider registration and admin approval
- Search by service type, location, rating, availability, and emergency support
- Booking with date/time, booking status tracking, and notifications
- Provider accept/reject/complete workflow
- Ratings and reviews
- Booking history
- Profile management
- Password reset demo flow
- Email OTP password reset with SMTP configuration
- CSRF protection on POST forms
- Stronger server-side validation
- Admin audit logging and protected admin registration
- Rule-based service recommendations
- Chat between customer and provider
- Emergency booking
- Stripe Checkout support with UPI/QR-style demo fallback
- Google Maps links for provider locations
- Admin dashboard for users, approvals, fake listing removal, and reports

## Demo Accounts

| Role | Email | Password |
| --- | --- | --- |
| Admin | admin@localconnect.test | admin123 |
| Customer | customer@localconnect.test | customer123 |
| Provider | provider@localconnect.test | provider123 |

## Run Locally

```powershell
cd "C:\Users\Kowshiek R\Documents\Codex\2026-06-03\mini-project-idea-neighborhood-service-portal\outputs\localconnect"
python -m flask --app app run --debug
```

Open: http://127.0.0.1:5000

The SQLite demo database is created automatically at `instance/localconnect.sqlite`.

## Production Configuration

Set these environment variables before deploying publicly:

```text
SECRET_KEY=use-a-long-random-value
DATABASE_URL=postgresql+psycopg://user:password@host:5432/localconnect
# or
DATABASE_URL=mysql+pymysql://user:password@host:3306/localconnect

MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=your-smtp-user
MAIL_PASSWORD=your-smtp-password
MAIL_FROM=noreply@yourdomain.com

ADMIN_REGISTRATION_KEY=private-admin-invite-key

STRIPE_SECRET_KEY=sk_live_or_test_key
STRIPE_CURRENCY=inr
ALLOW_DEMO_PAYMENTS=false
```

If `DATABASE_URL` is not set, the app falls back to SQLite for local development only.

## MySQL / PostgreSQL Notes

The app now uses SQLAlchemy and can run against PostgreSQL or MySQL using `DATABASE_URL`. The file `schema_mysql.sql` contains a MySQL-ready schema matching the project tables from the problem statement, plus the extra tables needed for notifications, chat, payments, emergency requests, admin reports, OTP reset, and audit logs.

For a college mini-project demo, SQLite is still available because it runs without installing a server database. For public use, deploy PostgreSQL or MySQL and set `DATABASE_URL`.

## Public Use Checklist

- Use PostgreSQL or MySQL, not SQLite.
- Set `SECRET_KEY` to a private random value.
- Configure SMTP for real OTP email delivery.
- Configure Stripe and disable demo payments.
- Keep admin registration private with `ADMIN_REGISTRATION_KEY`.
- Use HTTPS on your hosting platform.
