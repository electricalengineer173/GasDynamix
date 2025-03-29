# Note: this is not using for tabkecreation in neon so for table creation script look at database.py filr
# Whenever you need a new table or change an existing table , you add a new class here.
# from sqlalchemy.orm import declarative_base

# from sqlalchemy.orm import relationship
# from sqlalchemy import Boolean
# from sqlalchemy import (
#     Column, Integer, String, Float, Boolean, ForeignKey, Enum, Text, TIMESTAMP
# )
# from datetime import datetime, timezone
# from dynamictool.schemas import UnitType
# Base = declarative_base()

# class User(Base):
#     __tablename__ = "users"

#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String(50), unique=True, nullable=False)
#     password = Column(String(255), nullable=False)
#     role = Column(String, default="user")# Column(Enum("admin", "user", name="user_roles"), nullable=False, server_default="user")
#     created_at = Column(TIMESTAMP, default=lambda: datetime.now(timezone.utc), nullable=False)
#     email = Column(String, unique=True, index=True)
#     #items = relationship("Item", back_populates="owner")
#     projects = relationship("Project", back_populates="owner")

# # ---------------- PROJECT ----------------
# class Project(Base):
#     __tablename__ = "projects"

#     project_id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
#     name = Column(String(100), nullable=False)
#     description = Column(Text, nullable=True)
#     created_at =  Column(TIMESTAMP(timezone=True), default=datetime.now(timezone.utc))

#     owner = relationship("User", back_populates="projects")
#     cases = relationship("Case", back_populates="project")  # Added cases relationship
#     selected_components_composition = relationship("SelectedComponentGasComposition", single_parent=True,back_populates="project", cascade="all, delete-orphan")
#     inlet_conditions = relationship("InletCondition", back_populates="project", single_parent=True,cascade="all, delete-orphan")
#     calculated_properties = relationship("CalculatedProperty", back_populates="project",single_parent=True, cascade="all, delete-orphan")


# # ---------------- CASES ----------------
# class Case(Base):
#     __tablename__ = "cases"

#     case_id = Column(Integer, primary_key=True, index=True)  # Changed id to case_id
#     name = Column(String(100), nullable=False)
#     project_id = Column(Integer, ForeignKey("projects.project_id", ondelete="CASCADE"), nullable=False)
#     is_default = Column(Boolean, default=False)  # ✅ New field for "Case 1"

#     project = relationship("Project", back_populates="cases")  # Added back_populates
#     selected_components_composition = relationship("SelectedComponentGasComposition", back_populates="case")
#     inlet_conditions = relationship("InletCondition", back_populates="case")
#     calculated_properties = relationship("CalculatedProperty", back_populates="case")


# # ---------------- GASES ----------------
# class Gas(Base):
#     __tablename__ = "gases"

#     gas_id = Column(Integer, primary_key=True, index=True)
#     name = Column(String(50), nullable=False, unique=True)
#     molecular_weight = Column(Float, nullable=False)
#     density = Column(Float, nullable=False)
#     critical_pressure = Column(Float, nullable=False)
#     critical_temperature = Column(Float, nullable=False)
#     boiling_point = Column(Float, nullable=False)
#     toxicity_level = Column(Enum("low", "moderate", "high", name="toxicity_levels"), nullable=False)
#     explosive = Column(Boolean, default=False)
#     flammable = Column(Boolean, default=False)
#     corrosive = Column(Boolean, default=False)
#     oxidizing = Column(Boolean, default=False)
#     sour = Column(Boolean, default=False)
#     #created_at =  Column(TIMESTAMP(timezone=True), default=datetime.now(timezone.utc))


# # ---------------- SELECTED COMPONENTS Gas Composition----------------
# class SelectedComponentGasComposition(Base):
#     __tablename__ = "selected_components_composition"  # ✅ Fixed table name

#     id = Column(Integer, primary_key=True, index=True)
#     project_id = Column(Integer, ForeignKey("projects.project_id", ondelete="CASCADE"), nullable=False)
#     case_id = Column(Integer, ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)  
#     gas_id = Column(Integer, ForeignKey("gases.gas_id", ondelete="CASCADE"), nullable=False)
#     sequence_number = Column(Integer, nullable=False)
#     amount = Column(Float, nullable=False, default=0)  # ✅ Fixed default
#     unit = Column(Enum(UnitType), nullable=False, default=UnitType.MOL_PERCENT)  # ✅ Used Enum
#     assume_as_100 = Column(Boolean, default=False)

#     project = relationship("Project", back_populates="selected_components_composition",single_parent=True,cascade="all, delete-orphan")
#     case = relationship("Case", back_populates="selected_components_composition")  
#     gas = relationship("Gas")

# # ---------------- INLET CONDITIONS ----------------
# class InletCondition(Base):
#     __tablename__ = "inlet_conditions1"

#     id = Column(Integer, primary_key=True, index=True)
#     project_id = Column(Integer, ForeignKey("projects.project_id", ondelete="CASCADE"), nullable=False)
#     case_id = Column(Integer, ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)  # Added case_id
#     description = Column(Text, nullable=True)
#     ambient_pressure = Column(Float, nullable=False)
#     ambient_pressure_unit = Column(Enum("Pa", "bar", "atm", name="ambient_pressure_units"), nullable=False)
#     ambient_temperature = Column(Float, nullable=False)
#     ambient_temperature_unit = Column(Enum("K", "C", "F", name="ambient_temperature_units"), nullable=False)
#     guarantee_point = Column(Boolean, default=False)
#     suppress = Column(Boolean, default=False)
#     pressure = Column(Float, nullable=False)
#     pressure_unit = Column(Enum("Pa", "bar", "atm", name="pressure_units"), nullable=False)
#     temperature = Column(Float, nullable=False)
#     temperature_unit = Column(Enum("K", "C", "F", name="temperature_units"), nullable=False)
#     flow_type = Column(Enum("Mass flow", "Standard volumetric flow", "Volumetric flow", name="flow_types"), nullable=False)
#     flow_value = Column(Float, nullable=False)
#     flow_unit = Column(Enum("kg/s", "m³/s", "SLPM", name="flow_units"), nullable=False)

#     project = relationship("Project", back_populates="inlet_conditions",cascade="all, delete-orphan")
#     case = relationship("Case", back_populates="inlet_conditions")  # Added relationship


# #Relationship: This allows fetching all related items for a user
# #The items relationship is not a column in the database.
# #It enables automatic retrieval of all items linked to a user.

