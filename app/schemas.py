from pydantic import BaseModel
from typing import Optional

class UserBase(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: Optional[bool] = None
    group: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str
    group: str

class AdvertisementBase(BaseModel):
    title: str
    description: str

class AdvertisementCreate(AdvertisementBase):
    pass

class Advertisement(AdvertisementBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True