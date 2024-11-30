from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List, Optional
from passlib.context import CryptContext

# Конфигурация
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 48 * 60

# Модели данных
class User(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    disabled: bool = None
    group: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str
    group: str

# Инициализация приложения
app = FastAPI()

# Хранилище пользователей (для примера)
fake_users_db = {
    "user1": {
        "id": 1,
        "username": "user1",
        "full_name": "User One",
        "email": "user1@example.com",
        "hashed_password": "$2b$12$KIX9P0Q1m8QkL2yM0vZzOeQX5H5v6Z8g6hJx2vB0u3TqIhG5C6h5u",  # password
        "disabled": False,
        "group": "user",
    },
    "admin": {
        "id": 2,
        "username": "admin",
        "full_name": "Admin User",
        "email": "admin@example.com",
        "hashed_password": "$2b$12$KIX9P0Q1m8QkL2yM0vZzOeQX5H5v6Z8g6hJx2vB0u3TqIhG5C6h5u",  # password
        "disabled": False,
        "group": "admin",
    },
}

# Хэширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Безопасность
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Функции для работы с пользователями
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Роут для логина
@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username, "group": user.group}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Зависимость для получения текущего пользователя
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        group: str = payload.get("group")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, group=group)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Роуты для управления пользователями
@app.post("/user", response_model=User)
async def create_user(user: User):
    if user.group not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid group")
    fake_users_db[user.username] = user.dict()
    return user

@app.get("/user/{user_id}", response_model=User)
async def read_user(user_id: int):
    for user in fake_users_db.values():
        if user["id"] == user_id:
            return User(**user)
    raise HTTPException(status_code=404, detail="User not found")

@app.patch("/user/{user_id}", response_model=User)
async def update_user(user_id: int, user: User, current_user: User = Depends(get_current_user)):
    if current_user.group != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    for key, value in user.dict().items():
        if key in fake_users_db[current_user.username]:
            fake_users_db[current_user.username][key] = value
    return User(**fake_users_db[current_user.username])

@app.delete("/user/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.group != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    for username, user in list(fake_users_db.items()):
        if user["id"] == user_id:
            del fake_users_db[username]
            return {"detail": "User deleted"}
    raise HTTPException(status_code=404, detail="User not found")