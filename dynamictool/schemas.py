# Changes when API request/response structure changes.
# Defines Pydantic models for request/response validation.
# If a new API requires different input or output fields, this file needs updates.

from typing import List
from pydantic import BaseModel
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional
from enum import Enum

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    role: str  # e.g., "admin", "user"


class UserResponse(UserCreate):
    id: int
    #items: List[ItemResponse] = []  # Nested list of items

    class Config:
        from_attributes = True

# class ItemListResponse(BaseModel):
#     items: List[ItemResponse]


class ProjectCreate(BaseModel):
    name: str
    description : str
   

class ProjectResponse(ProjectCreate):
     project_id : int
     user_id: int
     created_at: datetime

     class Config:
        # orm_mode = True #allows compatibility with SQLAlchemy ORM model
        from_attributes = True


class CaseCreate(BaseModel):
    name: str


class CaseResponse(CaseCreate):
    case_id: int
    project_id:int

    class Config:
        # orm_mode = True #allows compatibility with SQLAlchemy ORM model
        from_attributes = True


# ✅ Gas Schema (Response)
class GasResponse(BaseModel):
    gas_id: int
    name: str
    molecular_weight: float
    density: float
    critical_pressure: float
    critical_temperature: float
    boiling_point: float
    toxicity: bool
    explosive: bool
    flammable: bool
    corrosive: bool
    oxidizing: bool
    sour: bool

    class Config:
        from_attributes = True



class GasNameResponse(BaseModel):
    #gas_id: int
    name: str
    class Config:
        from_attributes = True


# ✅ Gas Schema (Create)
class GasCreate(BaseModel):
    name: str
    molecular_weight: float
    density: float
    critical_pressure: float
    critical_temperature: float
    boiling_point: float
    toxicity: bool
    explosive: bool = False
    flammable: bool = False
    corrosive: bool = False
    oxidizing: bool = False
    sour: bool = False

# ✅ Schema for Selecting Gas
class SelectedComponentCreate(BaseModel):
    project_id: int
    case_id: int
    gas_id: int
  

class UnitType(str, Enum):
    MOL_PERCENT = "mol %"
    WEIGHT_PERCENT = "weight %"
    MOL_FRACTION = "mol fraction"
    WEIGHT_FRACTION = "weight fraction"

# class SelectedComponentCreateComposit(BaseModel):
#     project_id: int
#     case_id: int
#     gas_id: int
#     amount: float = 0
#     unit: UnitType = UnitType.MOL_PERCENT
#     assume_as_100: bool = False

class SelectedComponentCreateComposit(BaseModel):
    project_name: str
    case_name: str
    gas_name: str
    amount: float = 0
    unit: UnitType = UnitType.MOL_PERCENT
    assume_as_100: bool = False

class PressureUnit(str, Enum):
    pa = "Pa"
    bar = "bar"
    atm = "atm"

class TemperatureUnit(str, Enum):
    kelvin = "K"
    celsius = "C"
    fahrenheit = "F"

class FlowType(str, Enum):
    mass_flow = "Mass flow"
    standard_volumetric = "Standard volumetric flow"
    volumetric = "Volumetric flow"

class FlowUnit(str, Enum):
    kg_s = "kg/s"
    m3_s = "m³/s"
    slpm = "SLPM"

# ----- CASE CREATION SCHEMA -----
class CaseCreate(BaseModel):
    name: Optional[str] = None  # Name is optional because we auto-generate it

# ----- GAS COMPOSITION SCHEMA -----
class GasCompositionCreate(BaseModel):
    gas_id: int
    amount: float
    unit: UnitType
    assume_as_100: bool = False


class PressureUnitEnum(str, Enum):
    Pa = "Pa"
    bar = "bar"
    atm = "atm"

# Temperature Unit Enum
class TemperatureUnitEnum(str, Enum):
    K = "K"  # Kelvin
    C = "C"  # Celsius
    F = "F"  # Fahrenheit


# ----- INLET CONDITIONS SCHEMA -----
class InletConditionCreate(BaseModel):
    description: Optional[str]
    ambient_pressure: float
    ambient_pressure_unit:PressureUnitEnum
    ambient_temperature: float
    ambient_temperature_unit:TemperatureUnitEnum
    guarantee_point: bool = False
    suppress: bool = False
    pressure: float
    pressure_unit: PressureUnit
    temperature: float
    temperature_unit: TemperatureUnit
    flow_type: FlowType
    flow_value: float
    flow_unit: FlowUnit




class UnitTypeEnum1(str, Enum):
    MOL_PERCENT = "mol_percent"
    KG_MOL = "kg_mol"
    LITER = "liter"
    M3 = "m3"



# class PressureUnitEnum(str, Enum):
#     Pa = "Pa"
#     bar = "bar"
#     atm = "atm"

# # Temperature Unit Enum
# class TemperatureUnitEnum(str, Enum):
#     K = "K"  # Kelvin
#     C = "C"  # Celsius
#     F = "F"  # Fahrenheit

# Flow Unit Enum
class FlowUnitEnum(str, Enum):
    kg_per_s = "kg/s"
    cubic_meter_per_s = "m³/s"
    SLPM = "SLPM"  # Standard liters per minute

# Flow Type Enum
class FlowTypeEnum(str, Enum):
    mass_flow = "Mass flow"
    standard_volumetric_flow = "Standard volumetric flow"
    volumetric_flow = "Volumetric flow"


class GasCompositionResponse(BaseModel):
    project_id:int
    case_id:int
    composition_id: int
    gas_id: int
    sequence_number:int
    amount:float
    unit:UnitTypeEnum1
    percentage: float
    class Config:
        from_attributes = True  # ✅ Enable ORM conversion

class InletConditionResponse(BaseModel):
    id: int
    project_id:int
    case_id:int
    description: Optional[str]
    ambient_pressure: float
    ambient_pressure_unit:PressureUnitEnum
    ambient_temperature :float
    ambient_temperature_unit:TemperatureUnitEnum
    guarantee_point :bool
    suppress :bool
    pressure:float
    pressure_unit :PressureUnitEnum
    temperature : float
    temperature_unit : TemperatureUnitEnum  
    flow_type :FlowTypeEnum
    flow_unit : FlowUnitEnum
    flow_value : float
    class Config:
        from_attributes = True  # ✅ Enable ORM conversion


class CaseResponse1(BaseModel):
    case_id: int
    name: str
    project_id:int
    is_default: bool
    inlet_conditions: InletConditionResponse
    gas_composition: GasCompositionResponse
    class Config:
        from_attributes = True  # Allow from_orm to work

class ProjectResponse1(BaseModel):
    project_id: int
    name: str
    description: Optional[str] =[]
    cases: List[CaseResponse1] =[]
    class Config:
        from_attributes = True  # Ensures compatibility with ORM


class UserLogin(BaseModel):
    username: str
    password: str


# 🚀 Request Model
class GasSelectRequest(BaseModel):
    gas_name: str
    user_id: int  # Required to track selections per user

# 🚀 Response Model
class GasResponse(BaseModel):
    gas_id: int
    name: str
    
# ✅ Response Model
class SelectedGasResponse(BaseModel):
    gas_id: int
    gas_name: str

# ✅ Request Model
class GasRemoveRequest(BaseModel):
    gas_name: str
    user_id: int