from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserInDB(BaseModel):
    id: int
    email: str
    password_hash: Optional[str] = None


# Nuevos modelos para archivos
class FileBase(BaseModel):
    filename: str
    filesize: int

class FileCreate(FileBase):
    pass

class FileInDB(FileBase):
    id: int
    user_id: int
    filepath: str
    uploaded_at: str

class ShareFileRequest(BaseModel):
    file_id: int
    shared_with_email: str
