import bcrypt
import datetime, os
import fastapi
import uvicorn
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel


api = fastapi.FastAPI()

# Dummy in-memory user storage
fake_users_db = {}

# JWT settings
SECRET_KEY = "yHkVWxS0cDWq3q5k9mDvqQ_VFgRSxUpiQ4RcXqP0Er4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour token

# OAuth2 Bearer Token scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="signin"
)  # tokenUrl is just a hint for docs


# Request models
class SignUpRequest(BaseModel):
    username: str
    password: str


class SignInRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_access_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    to_encode = data.copy()
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


# 🛡 Protected endpoint
@api.get("/hello")
def hello(token: str = Depends(oauth2_scheme)) -> dict[str, str]:
    username = verify_token(token)
    return {"message": f"Hello {username}!"}


@api.post("/signup")
def signup(user: SignUpRequest) -> dict[str, str]:
    if user.username in fake_users_db:
        return {"error": "User already exists"}

    hashed_pw = hash_password(user.password)
    fake_users_db[user.username] = hashed_pw
    return {"message": "User created successfully"}


@api.post("/signin")
def signin(user: SignInRequest) -> dict[str, str]:
    stored_hashed_pw = fake_users_db.get(user.username)

    if not stored_hashed_pw:
        return {"error": "User not found"}

    if not verify_password(user.password, stored_hashed_pw):
        return {"error": "Incorrect password"}

    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "type": "access"},
        expires_delta=access_token_expires,
    )

    refresh_token_expires = datetime.timedelta(days=7)  # 7 days validity
    refresh_token = create_access_token(
        data={"sub": user.username, "type": "refresh"},
        expires_delta=refresh_token_expires,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@api.post("/refresh")
def refresh_token(request: RefreshRequest) -> dict[str, str]:
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")

        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
            )

        new_access_token_expires = datetime.timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
        new_access_token = create_access_token(
            data={"sub": username, "type": "access"},
            expires_delta=new_access_token_expires,
        )

        return {"access_token": new_access_token, "token_type": "bearer"}

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )


if __name__ == "__main__":
    print("Starting webserver...")
    uvicorn.run(
        api,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        proxy_headers=True,
    )
