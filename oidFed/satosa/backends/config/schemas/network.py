from typing import Optional

from pydantic import BaseModel, Field, StrictInt


class Session(BaseModel):
    timeout: Optional[StrictInt] = 6


class Connection(BaseModel):
    ssl: Optional[bool] = True


class NetworkConfigSchema(BaseModel):
    connection: Optional[Connection] = Field(default_factory=Connection)
    session: Optional[Session] = Field(default_factory=Session)
    verify_ssl: Optional[bool] = True
    request_with_trustchain: Optional[bool] = True
