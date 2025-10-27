"""
Authentication Endpoints for main.py

Add these endpoints to backend/main.py after the existing imports and before the vote endpoint.
Also update imports at the top of main.py.
"""

# ============================================================================
# ADD THESE IMPORTS TO THE TOP OF main.py
# ============================================================================

"""
from auth_service import get_auth_service
from middleware.auth_middleware import (
    get_current_user,
    get_optional_user,
    require_admin,
    require_vetter,
    require_reviewer,
    get_current_user_or_api_key
)
from schemas.auth_schemas import (
    RegisterRequest,
    LoginRequest,
    RefreshTokenRequest,
    PasswordChangeRequest,
    TokenResponse,
    UserResponse,
    ErrorResponse,
    CurrentUser
)
"""

# ============================================================================
# AUTHENTICATION ENDPOINTS - Add these to main.py
# ============================================================================

@app.post("/auth/register", response_model=TokenResponse, tags=["Authentication"])
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    
    Creates a new user account and returns access/refresh tokens.
    Default role is 'submitter' unless specified.
    
    **Roles**:
    - `submitter`: Can submit content for review
    - `reviewer`: Can vote on submissions
    - `vetter`: Can issue blind credentials
    - `admin`: Full system access
    """
    auth_service = get_auth_service()
    
    # Create user
    success, user_id, error = await auth_service.create_user(
        user_data=request,
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
"""
Authentication Endpoints for main.py

Add these endpoints to backend/main.py after the existing imports and before the vote endpoint.
Also update imports at the top of main.py.
"""

# ============================================================================
# ADD THESE IMPORTS TO THE TOP OF main.py
# ============================================================================

"""
from auth_service import get_auth_service
from middleware.auth_middleware import (
    get_current_user,
    get_optional_user,
    require_admin,
    require_vetter,
    require_reviewer,
    get_current_user_or_api_key
)
from schemas.auth_schemas import (
    RegisterRequest,
    LoginRequest,
    RefreshTokenRequest,
    PasswordChangeRequest,
    TokenResponse,
    UserResponse,
    ErrorResponse,
    CurrentUser
)
"""

# ============================================================================
# AUTHENTICATION ENDPOINTS - Add these to main.py
# ============================================================================

@app.post("/auth/register", response_model=TokenResponse, tags=["Authentication"])
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    
    Creates a new user account and returns access/refresh tokens.
    Default role is 'submitter' unless specified.
    
    **Roles**:
    - `submitter`: Can submit content for review
    - `reviewer`: Can vote on submissions
    - `vetter`: Can issue blind credentials
    - `admin`: Full system access
    """
    auth_service = get_auth_service()
    
    # Create user
    success, user_id, error = await auth_service.create_user(
        user_data=request,
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Get user data
    user_data = await auth_service.get_user_by_id(user_id, db)
    
    # Generate tokens
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with username and password
    
    Returns JWT access and refresh tokens on successful authentication.
    """
    auth_service = get_auth_service()
    
    # Authenticate user
    user_data = await auth_service.authenticate_user(
        username=request.username,
        password=request.password,
        db=db
    )
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    from models import User as UserModel
    await db.execute(
        update(UserModel)
        .where(UserModel.id == user_data["id"])
        .values(last_login_at=datetime.utcnow())
    )
    await db.commit()
    
    # Generate tokens
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.post("/auth/refresh", response_model=TokenResponse, tags=["Authentication"])
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token
    
    Use this endpoint to get a new access token when it expires.
    """
    auth_service = get_auth_service()
    
    # Verify refresh token
    payload = auth_service.verify_token(request.refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check token type
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user
    user_id = int(payload.get("sub"))
    user_data = await auth_service.get_user_by_id(user_id, db)
    
    if not user_data or not user_data.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate new tokens
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_info(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current authenticated user information
    
    Returns detailed information about the currently authenticated user.
    """
    auth_service = get_auth_service()
    
    user_data = await auth_service.get_user_by_id(current_user.id, db)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(**user_data)


@app.post("/auth/change-password", tags=["Authentication"])
async def change_password(
    request: PasswordChangeRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Change user password
    
    Requires current password for verification.
    """
    auth_service = get_auth_service()
    
    # Verify current password
    from models import User as UserModel
    result = await db.execute(
        select(UserModel).where(UserModel.id == current_user.id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not auth_service.verify_password(request.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    new_password_hash = auth_service.hash_password(request.new_password)
    await db.execute(
        update(UserModel)
        .where(UserModel.id == current_user.id)
        .values(password_hash=new_password_hash)
    )
    await db.commit()
    
    logger.info(f"Password changed for user {current_user.username}")
    
    return {"message": "Password changed successfully"}


# ============================================================================
# UPDATE EXISTING ENDPOINTS TO REQUIRE AUTHENTICATION
# ============================================================================

"""
Update these existing endpoints in main.py:

1. POST /api/v1/vote - Add require_reviewer dependency:
   async def submit_vote(
       vote_request: VoteRequest,
       request: Request,
       current_user: CurrentUser = Depends(require_reviewer),  # <-- ADD THIS
       db: AsyncSession = Depends(get_db)
   ):

2. POST /api/v1/rings - Add require_admin dependency:
   async def create_ring(
       ring_data: dict,
       current_user: CurrentUser = Depends(require_admin),  # <-- ADD THIS
       db: AsyncSession = Depends(get_db)
   ):

3. POST /api/v1/present-credential - Add require_reviewer dependency:
   async def present_credential(
       credential_request: CredentialRequest,
       current_user: CurrentUser = Depends(require_reviewer),  # <-- ADD THIS
       db: AsyncSession = Depends(get_db)
   ):

4. GET /api/v1/statistics - Add require_admin dependency:
   async def get_statistics(
       current_user: CurrentUser = Depends(require_admin),  # <-- ADD THIS
       db: AsyncSession = Depends(get_db)
   ):

5. Keep /health and /api/v1/submissions public (no auth required)
"""