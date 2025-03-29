from fastapi import FastAPI, Depends
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from dynamictool.schemas import ProjectResponse1,GasRemoveRequest, SelectedGasResponse,GasSelectRequest, GasResponse, CaseResponse1, SelectedComponentCreateComposit,GasCompositionCreate, InletConditionCreate,GasNameResponse,GasResponse,GasCreate,SelectedComponentCreate, CaseCreate,CaseResponse, UserCreate, ProjectCreate,ProjectResponse, UserResponse# Fix Import
from dynamictool.database import Gas,User,Project,Case,InletCondition,SelectedComponentGasComposition,SelectedGas
from dynamictool.database import get_db, startup_event
from sqlalchemy.future import select
from dynamictool.security import verify_password
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dynamictool.jwt_handler import create_access_token
from fastapi import HTTPException,status
from dynamictool.jwt_handler import get_current_user  # Import JWT validation function
from dynamictool.security import pwd_context
from fastapi.responses import JSONResponse
from fastapi import Request
from typing import List
from datetime import datetime, timezone
from sqlalchemy.orm import selectinload
from sqlalchemy.orm import joinedload
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
import pandas as pd
from sqlalchemy import delete
from sqlalchemy.inspection import inspect
from sqlalchemy import or_
from fastapi import Query
from fastapi.middleware.cors import CORSMiddleware

# ✅ Use `lifespan` to ensure tables are created
@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup_event()  # ✅ Ensure tables are created on startup
    yield  # Application runs
    print("✅ FastAPI shutdown complete.")

# ✅ Initialize FastAPI app with lifespan event
app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    #allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

@app.get("/")
async def read_root():
    return {"message": "FastAPI is running!"}

@app.post("/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await db.execute(select(User).where(User.username == form_data.username))
    user = user.scalars().first()
    
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token({"id": user.id, "sub": user.username, "role": user.role})

    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access
        max_age=60 * 60 * 24,  # Expires in 1 day
        secure=True,  # Use only on HTTPS
        samesite="Strict",
    )

    return {"access_token": access_token, "token_type": "bearer", "role": user.role,"response":response}


@app.get("/admin/users", response_model=List[UserResponse])
async def get_all_users(db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    # ✅ Only allow admin to access user list
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view users")

    result = await db.execute(select(User))
    users = result.scalars().all()
    return users


@app.post("/admin/create-users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),  # Require authentication
):
    # 🔹 Ensure only admins can create users
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create users"
        )

    # 🔹 Check if the user already exists (Use Async Execution)
    result = await db.execute(select(User).where(User.username == user.username))
    existing_user = result.scalar_one_or_none()  # ✅ Async-friendly equivalent of `.first()`

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )

    # 🔹 Hash the password before storing it
    hashed_password = pwd_context.hash(user.password)

    # 🔹 Create a new user
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        role=user.role,
        created_at= datetime.now(timezone.utc)
    )
    
    db.add(new_user)  # No need to `await` add()
    await db.commit()  # Use await
    await db.refresh(new_user)  # Use await

    return {"message": "User created successfully", "username": new_user.username, "role": new_user.role,"time":new_user.created_at}


@app.delete("admin/users/{username}", response_model=dict)
async def delete_user(username: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    # ✅ Only admin can delete users
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete users")

    # Use `await` with async queries
    result = await db.execute(select(User).filter(User.username == username))
    db_user = result.scalar_one_or_none()
    print("db user",db_user)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(db_user)
    await db.commit()
    return {"message": f"User '{username}' has been deleted"}


@app.get("/projects/", response_model=list[ProjectResponse])
async def get_projects(
    db: AsyncSession = Depends(get_db), 
    user: dict = Depends(get_current_user)  
):
    # ✅ Fetch projects owned by the logged-in user
    #result = await db.execute(select(Project).where(Project.user_id == user["id"]))
    print(user["id"])
    if user["role"] == "admin":  
        result = await db.execute(select(Project))  # Fetch all projects
    else:
        result = await db.execute(select(Project).where(Project.user_id == user["id"]))  # Fetch only user projects
    
    projects = result.scalars().all()
    return projects


@app.delete("/admin/projects/{project_name}/", status_code=204)
async def delete_project(
    project_name: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),  # Get the current user
):
    # Check if the current user is an admin
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete projects")
    
    # ✅ Retrieve the project to delete
    result = await db.execute(select(Project).where(Project.name == project_name))
    project = result.scalars().first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get the project_id for deletion purposes
    project_id = project.project_id

    # ✅ Delete associated data from related tables explicitly (optional, cascades should handle this)
    

    # Example: Delete selected component gas composition
    await db.execute(
        delete(SelectedComponentGasComposition).where(SelectedComponentGasComposition.project_id == project_id)
    )

    # Example: Delete inlet conditions
    await db.execute(
        delete(InletCondition).where(InletCondition.project_id == project_id)
    )

    # Finally, delete the project itself
    await db.delete(project)
    await db.commit()

    return {"detail": "Project and its associated data deleted successfully"}



# 🚀 Admin Adds a New Gas (🔒 Protected Route)
@app.post("/admin/single-gase/", response_model=GasResponse)
async def add_gas(
    gas: GasCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user)  # Only admins can add gases
):
    
        # ✅ Ensure only admins can create items
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create items"
        )
    new_gas =  Gas(
        name=gas.name,
        molecular_weight=gas.molecular_weight,
        density=gas.density,
        critical_pressure=gas.critical_pressure,
        critical_temperature=gas.critical_temperature,
        boiling_point=gas.boiling_point,
        toxicity=gas.toxicity,
        explosive=gas.explosive,
        flammable=gas.flammable,
        corrosive=gas.corrosive,
        oxidizing=gas.oxidizing,
        sour=gas.sour,
        #created_at= datetime.now(timezone.utc)
        
    )
    db.add(new_gas)
    await db.commit()
    await db.refresh(new_gas)
    
    return new_gas


# ✅ Upload CSV and insert data
@app.post("/admin/upload-gases-csv/")
async def upload_gases(file: UploadFile = File(...), db: AsyncSession = Depends(get_db),user: dict = Depends(get_current_user)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are allowed")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to add gases")
    # ✅ Read CSV file
    df = pd.read_csv(file.file)

    # ✅ Ensure required columns exist
    expected_columns = {
        "name", "critical_temperature", "critical_pressure", "boiling_point", "density",
        "molecular_weight", "toxicity", "explosive", "flammable", "corrosive", "oxidizing"
    }
    if not expected_columns.issubset(df.columns):
        raise HTTPException(status_code=400, detail=f"Missing columns: {expected_columns - set(df.columns)}")

    # ✅ Convert boolean columns
    boolean_columns = ["toxicity","explosive", "flammable", "corrosive", "oxidizing"]
    for col in boolean_columns:
        df[col] = df[col].astype(bool)

    # # ✅ Convert toxicity level to Enum
    # valid_toxicity_levels = {"low", "moderate", "high"}
    # if not set(df["toxicity_level"]).issubset(valid_toxicity_levels):
    #     raise HTTPException(status_code=400, detail="Invalid values in toxicity_level column")

    # ✅ Insert into database
    gases = [
        Gas(
            name=row["name"],
            critical_temperature=row["critical_temperature"],
            critical_pressure=row["critical_pressure"],
            boiling_point=row["boiling_point"],
            density=row["density"],
            molecular_weight=row["molecular_weight"],
            toxicity=row["toxicity"],
            explosive=row["explosive"],
            flammable=row["flammable"],
            corrosive=row["corrosive"],
            oxidizing=row["oxidizing"],
            sour=False  # Default value since it's missing in CSV
        )
        for _, row in df.iterrows()
    ]

    db.add_all(gases)
    await db.commit()

    return {"message": "Gases data uploaded successfully"}


@app.get("/user/projects/project_name/", response_model=list[ProjectResponse])
async def search_projects(
    name: str,  
    db: AsyncSession = Depends(get_db), 
    user: dict = Depends(get_current_user)  
):
    # ✅ Search for projects that match the name and belong to the logged-in user
    result = await db.execute(
        select(Project).where(Project.user_id == user["id"], Project.name.ilike(f"%{name}%"))
    )
    projects = result.scalars().all()

    if not projects:
        raise HTTPException(status_code=404, detail="No matching projects found")

    return projects

@app.post("/user/create-projects/", response_model=ProjectResponse)
async def create_project(
    project: ProjectCreate, 
    db: AsyncSession = Depends(get_db), 
    user: dict = Depends(get_current_user)  # ✅ Ensure authentication
):
    # ✅ Create a new project linked to the logged-in user
    db_project = Project(name=project.name, description=project.description, user_id=user["id"])
    db.add(db_project)
    await db.commit()
    await db.refresh(db_project)

    # ✅ Automatically create "Case 1" (non-deletable)
    db_case = Case(name="Case 1", project_id=db_project.project_id, is_default=True)
    db.add(db_case)
    await db.commit()
    await db.refresh(db_case)

    return db_project


#  User Searches for a Gas (ASYNC)
@app.get("/user/gases/", response_model=List[GasNameResponse])
async def search_gases(
    name: str,  # Required search parameter
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user)  # User must be logged in
):
    result = await db.execute(select(Gas).where(Gas.name.ilike(f"%{name}%")))
    gases = result.scalars().all()

    if not gases:
        raise HTTPException(status_code=404, detail="No matching gases found")

    return gases

# Temporary storage (Replace with DB in production)
selected_gases = []

from pydantic import BaseModel



# ✅ API: Select a Gas
@app.post("/user/gases-select/", response_model=List[GasResponse])
async def select_gas(
    request: GasSelectRequest,
    db: AsyncSession = Depends(get_db)
):
    # 1️⃣ Check if the gas exists
    result = await db.execute(select(Gas).where(Gas.name == request.gas_name))
    gas = result.scalars().first()

    if not gas:
        raise HTTPException(status_code=404, detail="Gas not found")

    # 2️⃣ Check if the gas is already selected by the user
    existing_selection = await db.execute(
        select(SelectedGas).where(
            SelectedGas.gas_name == request.gas_name,
            SelectedGas.user_id == request.user_id
        )
    )
    if existing_selection.scalars().first():
        raise HTTPException(status_code=400, detail="Gas already selected")

    # 3️⃣ Insert into SelectedGas table
    new_selection = SelectedGas(user_id=request.user_id, gas_name=request.gas_name)
    db.add(new_selection)
    await db.commit()

    # 4️⃣ Fetch updated selected gases for the user
    selected_result = await db.execute(
        select(Gas).join(SelectedGas).where(SelectedGas.user_id == request.user_id)
    )
    selected_gases = selected_result.scalars().all()

    return [{"gas_id": g.gas_id, "name": g.name} for g in selected_gases]



# ✅ API: Remove a Gas
@app.delete("/user/gases-remove/", response_model=List[dict])
async def remove_gas(
    request: GasRemoveRequest,
    db: AsyncSession = Depends(get_db)
):
    # 1️⃣ Check if the gas is in the user's selection
    existing_selection = await db.execute(
        select(SelectedGas).where(
            SelectedGas.gas_name == request.gas_name,
            SelectedGas.user_id == request.user_id
        )
    )
    selected_gas = existing_selection.scalars().first()

    if not selected_gas:
        raise HTTPException(status_code=404, detail="Gas not found in selection")

    # 2️⃣ Remove the selected gas
    await db.delete(selected_gas)
    await db.commit()

    # 3️⃣ Fetch updated selected gases for the user
    selected_result = await db.execute(
        select(Gas).join(SelectedGas).where(SelectedGas.user_id == request.user_id)
    )
    selected_gases = selected_result.scalars().all()

    return [{"gas_id": g.gas_id, "name": g.name} for g in selected_gases]



# ✅ API: Fetch Selected Gases for a User
@app.get("/user/gases-selected/", response_model=List[SelectedGasResponse])
async def get_selected_gases(user_id: int, db: AsyncSession = Depends(get_db)):
    # 1️⃣ Fetch selected gases for the given user
    selected_result = await db.execute(
        select(Gas.gas_id, Gas.name)
        .join(SelectedGas, SelectedGas.gas_name == Gas.name)
        .where(SelectedGas.user_id == user_id)
    )
    selected_gases = selected_result.all()

    if not selected_gases:
        raise HTTPException(status_code=404, detail="No gases selected")

    # 2️⃣ Return selected gases as a list
    return [{"gas_id": gas.gas_id, "gas_name": gas.name} for gas in selected_gases]


#----------------------------------------- Selected Gas Composition---------------------------------------------
@app.post("/user/gas_composition/")
async def select_gas_for_case(
    data: SelectedComponentCreateComposit,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user)  # User must be logged in
):
    # ✅ Check if the gas exists

    stmt = select(Gas.gas_id).where(Gas.name == data.gas_name)  # Query to get gas_id
    result = await db.execute(stmt)  # Execute query
    gas_id = result.scalar() # Extract gas_id

    if not gas_id:
        raise HTTPException(status_code=404, detail="Gas not found")  # Handle missing gas
    
    gas = await db.execute(select(Gas).where(Gas.gas_id == gas_id))
    gas = gas.scalars().first()

    stmt = select(Case.case_id).where(Case.name == data.case_name)  # Query to get gas_id
    result = await db.execute(stmt)  # Execute query
    case_id = result.scalar() # Extract gas_id   

    if not case_id:
        raise HTTPException(status_code=404, detail="Cas not found")  # Handle missing gas

    case = await db.execute(select(Case).where(Case.case_id == case_id))
    case = case.scalars().first()


    stmt = select(Project.project_id).where(Project.name == data.project_name)  # Query to get gas_id
    result = await db.execute(stmt)  # Execute query
    project_id = result.scalar() # Extract gas_id   

    if not project_id:
        raise HTTPException(status_code=404, detail="Project not found")  # Handle missing gas

    project = await db.execute(select(Project).where(Project.project_id == project_id))
    project = project.scalars().first()


    # ✅ Check if gas_id already exists for the given project_id & case_id
    existing_gas = await db.execute(
        select(SelectedComponentGasComposition).where(
        SelectedComponentGasComposition.project_id == project_id,
        SelectedComponentGasComposition.case_id == case_id,
        SelectedComponentGasComposition.gas_id == gas_id
        )
    )
    if existing_gas.scalars().first():
        raise HTTPException(status_code=400, detail="Gas already added for this case and project")

    # ✅ Get the current highest sequence number for the given project_id & case_id
    current_max_sequence = await db.execute(
        select(SelectedComponentGasComposition.sequence_number)
        .where(
            SelectedComponentGasComposition.project_id == project_id,
            SelectedComponentGasComposition.case_id == case_id
        )
        .order_by(SelectedComponentGasComposition.sequence_number.desc())  # Get the max sequence number
        .limit(1)
    )
    max_sequence = current_max_sequence.scalars().first()
    new_sequence_number = (max_sequence + 1) if max_sequence else 1  # Assign next sequence number

    # ✅ Save the gas selection with auto-generated sequence_number
    selected_gas = SelectedComponentGasComposition(
        project_id=project_id,
        case_id=case_id,
        gas_id= gas_id,
        sequence_number=new_sequence_number  # Auto-assigned
    )
    db.add(selected_gas)
    await db.commit()
    await db.refresh(selected_gas)

    # ✅ Fetch all selected components for the given project_id & case_id
    selected_components_query = await db.execute(
        select(SelectedComponentGasComposition).where(
            SelectedComponentGasComposition.project_id == project_id,
            SelectedComponentGasComposition.case_id == case_id
        ).order_by(SelectedComponentGasComposition.sequence_number)
    )
    selected_components = selected_components_query.scalars().all()

    # ✅ Return response as a plain dictionary (No Response Model)
    return {
        "message": "Gas added to selected components!",
        "selected_components": [
            {
                "id": component.id,
                "project_id": component.project_id,
                "case_id": component.case_id,
                "gas_id": component.gas_id,
                "sequence_number": component.sequence_number
            }
            for component in selected_components
        ]
    }


@app.post("/user/CaseRequiredParameters/")
async def create_case(
    project_id: int,
    inlet_conditions: list[InletConditionCreate],
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user)  # Ensure user is logged in
):
    # ✅ Check if the project belongs to the logged-in user
    project = await db.execute(
        select(Project).where(Project.project_id == project_id, Project.user_id == user["id"])
    )
    project = project.scalars().first()
    
    if not project:
        raise HTTPException(
            status_code=403,
            detail="This project does not belong to the logged-in user. Select or enter the correct project."
        )

    # ✅ Get the current highest case number for the project
    result = await db.execute(select(Case).where(Case.project_id == project_id))
    existing_cases = result.scalars().all()
    next_case_number = len(existing_cases) + 1

    # ✅ Create new case
    new_case = Case(
        name=f"Case {next_case_number}",
        project_id=project_id,
        is_default=False
    )
    db.add(new_case)
    await db.flush()  # Get new case_id

    # ✅ Insert Inlet Conditions
    for inlet in inlet_conditions:
        db.add(InletCondition(
            project_id=project_id,
            case_id=new_case.case_id,
            description=inlet.description,
            ambient_pressure=inlet.ambient_pressure,
            ambient_pressure_unit=inlet.ambient_pressure_unit,
            ambient_temperature=inlet.ambient_temperature,
            ambient_temperature_unit=inlet.ambient_temperature_unit,
            guarantee_point=inlet.guarantee_point,
            suppress=inlet.suppress,
            pressure=inlet.pressure,
            pressure_unit=inlet.pressure_unit,
            temperature=inlet.temperature,
            temperature_unit=inlet.temperature_unit,
            flow_type=inlet.flow_type,
            flow_value=inlet.flow_value,
            flow_unit=inlet.flow_unit
        ))

    await db.commit()
    return {"message": "Case created successfully", "case_id": new_case.case_id}



@app.get("/projects-details/")
async def get_project(
    project_id: int = None, 
    name: str = None,  
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    if not project_id and not name:
        raise HTTPException(status_code=400, detail="Provide either project_id or name")

    # ✅ Fetch Project with Cases, Components, and Inlets properly nested
    stmt = (
        select(Project)
        .filter(
            Project.user_id == user["id"],
            or_(Project.project_id == project_id, Project.name == name)
        )
        .options(
            joinedload(Project.cases)
                .joinedload(Case.selected_components_composition)
                .joinedload(SelectedComponentGasComposition.gas),  # ✅ Load Gas details under each Case
            joinedload(Project.cases)
                .joinedload(Case.inlet_conditions)  # ✅ Load Inlet Conditions under each Case
        )
    )

    result = await db.execute(stmt)
    project = result.scalars().first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # ✅ Convert project to a dictionary with properly nested cases
    project_dict = {
        "project_id": project.project_id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at,
        "cases": [
            {
                "case_id": case.case_id,
                "name": case.name,
                "is_default": case.is_default,
                "selected_components_composition": [
                    {
                        "id": comp.id,
                        "gas_name": comp.gas.name,  # ✅ Correctly placed under the case
                        "sequence_number": comp.sequence_number,
                        "amount": comp.amount,
                        "unit": comp.unit.value,
                        "assume_as_100": comp.assume_as_100
                    }
                    for comp in case.selected_components_composition
                ],
                "inlet_conditions": [
                    {
                        "id": inlet.id,
                        "description": inlet.description,
                        "ambient_pressure": inlet.ambient_pressure,
                        "ambient_pressure_unit": inlet.ambient_pressure_unit,
                        "ambient_temperature": inlet.ambient_temperature,
                        "ambient_temperature_unit": inlet.ambient_temperature_unit,
                        "guarantee_point":inlet.guarantee_point,
                        "suppress":inlet.suppress,
                        "pressure": inlet.pressure,
                        "pressure_unit": inlet.pressure_unit,
                        "temperature": inlet.temperature,
                        "temperature_unit": inlet.temperature_unit,
                        "flow_type": inlet.flow_type,
                        "flow_value": inlet.flow_value,
                        "flow_unit": inlet.flow_unit
                    }
                    for inlet in case.inlet_conditions
                ]
            }
            for case in project.cases
        ]
    }

    return project_dict