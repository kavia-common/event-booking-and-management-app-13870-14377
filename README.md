# event-booking-and-management-app-13870-14377

This repository contains multiple services. The UserService provides user registration, authentication (bearer token), profile management, RBAC, recovery endpoints, and admin user management.

Run the service locally:

- Create a virtual environment and install requirements from `UserService/requirements.txt`.
- Optionally copy `UserService/.env.example` to `.env` and set `USERSERVICE_SECRET` for stable tokens.
- Start the API:

```
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

OpenAPI docs:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

Generate OpenAPI JSON for interface sharing:

```
python -m src.api.generate_openapi
```