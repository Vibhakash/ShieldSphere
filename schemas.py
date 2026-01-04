from pydantic import BaseModel

class EmailRequest(BaseModel):
    email: str

class URLRequest(BaseModel):
    url: str
