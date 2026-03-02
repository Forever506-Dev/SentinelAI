from pydantic import BaseModel
import uuid

class T(BaseModel):
    id: str
    model_config = {'from_attributes': True}

class Obj:
    id = uuid.uuid4()

try:
    print(T.model_validate(Obj()))
except Exception as e:
    print(f'Error: {e}')
