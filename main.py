import os
import secrets

from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="Warmi Bypass Tools Auth")

origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "*").split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def configured_credentials() -> tuple[str, str]:
    return os.getenv("APP_USERNAME", ""), os.getenv("APP_PASSWORD", "")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/user/auth/")
def authenticate(
    username: str = Form(default=""),
    password: str = Form(default=""),
    mac_adress: str = Form(default=""),
) -> dict[str, bool]:
    expected_user, expected_password = configured_credentials()
    valid = bool(expected_user and expected_password) and secrets.compare_digest(username, expected_user) and secrets.compare_digest(password, expected_password)
    return {"active": valid, "auth": valid}
