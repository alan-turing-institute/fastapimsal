# FastAPI Auth

Authenticate users with FastAPI using the [Microsoft MSAL Library](https://msal-python.readthedocs.io/en/latest/) and Azure Active Directory.

## Getting started


### Python dependencies

To get started install [Poetry](https://python-poetry.org/docs/).

Then ensure all dependencies are installed:

```bash
poetry install
```

### Pre-commit

Run to make CI-tests pass
```bash
poetry run pre-commit run --all-files
```

Note: `SAFETY_API_KEY` environment variable needs to be set to run
the pre-commit hooks. Create an account with the [Safety package](https://platform.safetycli.com/)
and then navigate to Organization > API keys to fetch the key. Once
the key has been obtained, set the variable in your terminal using:

```bash
export SAFETY_API_KEY=your-api-key
```

## Examples
See [examples/app.py](examples/app.py) for a simple example.

Create a `.auth.env` file:

```bash
echo "session_expire_time_minutes=1
session_secret=<Session-Cookie-Secret>
client_id=<Application-client-id>
client_secret=<Application-Client-secret>
tenant_id=<Tenant-id" > .auth.env
```

For the `session_secret` its a good idea to create a secret with `openssl rand -hex 32`


To run the example

```bash
poetry run uvicorn --reload --app-dir examples app:app --reload-dir examples
```
