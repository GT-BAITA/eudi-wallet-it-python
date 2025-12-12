from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt


class Session(BaseModel):
    timeout: Optional[StrictInt] = 6


class Connection(BaseModel):
    ssl: Optional[StrictBool] = True


class NetworkConfigSchema(BaseModel):
    connection: Optional[Connection] = Field(default_factory=Connection)
    session: Optional[Session] = Field(default_factory=Session)
    verify_ssl: Optional[StrictBool] = True
