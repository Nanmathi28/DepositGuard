import secrets
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi import File, Form, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.models import (AuditEvent, AuthSession, EvidenceCheck, FDRDocument, FDRRecord,
                        Institution, InstitutionMembership, SecurityAuditEvent, User)
from app.models.domain import utc_now
from app.models.auth import LoginFailure
from app.schemas.auth import (ActiveStateRequest, AuthSessionResponse, ChangePasswordRequest,
                              LoginRequest, MembershipRequest, MembershipResponse,
                              PasswordResetRequest, UserProvisionRequest, UserResponse,
                              UserRegistrationRequest, UserRegistrationResponse)
from app.services.auth import (AuthContext, CSRF_COOKIE, SESSION_COOKIE, authenticate,
                               create_user, get_auth_context, hash_secret,
                               password_hasher, record_security_event,
                               require_institution, require_system_admin,
                               validate_password)
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from app.schemas.domain import (
    AuditEventResponse,
    DashboardSummaryResponse,
    FDRRecordCreate,
    FDRRecordResponse,
    InstitutionCreate,
    InstitutionResponse,
    TransitionRequest,
    WorkflowConfigurationResponse,
)
from app.schemas.health import HealthResponse
from app.schemas.graph import GraphPolicyResponse, RelationshipCreate, RelationshipResponse, TraversalResponse
from app.schemas.priority import PriorityPolicyResponse, PriorityQueueResponse, UrgencyScoreResponse
from app.schemas.uploads import (
    DocumentResponse,
    DocumentVersionResponse,
    EvidenceCheckResponse,
    IntegrityCheckRequest,
    UploadPolicyResponse,
)
from app.services.documents import (
    DocumentCategoryNotConfigured,
    DocumentService,
    DocumentVersionConflict,
)
from app.services.storage import (
    PrivateLocalStorage,
    StorageConfigurationError,
    StorageUnavailable,
    UploadPolicyError,
    UploadPolicyLoader,
    UploadRejected,
    UploadTooLarge,
)
from app.services.workflow import (
    EntityNotFound,
    InvalidTransition,
    WorkflowService,
)
from app.services.graph import GraphPolicyError, GraphService, InvalidRelationship, RelationshipConflict
from app.services.priority import PriorityConfigurationError, PriorityScoringService

from app.schemas.auth import BootstrapAdminRequest

public_router = APIRouter()

@public_router.post("/auth/bootstrap-admin", tags=["authentication"])
def bootstrap_admin(
    payload: BootstrapAdminRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    settings = get_settings()
    configured_secret = settings.bootstrap_secret
    supplied_secret = request.headers.get("X-Bootstrap-Secret", "")

    if not configured_secret or not secrets.compare_digest(
        supplied_secret, configured_secret
    ):
        raise HTTPException(status_code=403, detail="Bootstrap access is unavailable.")

    existing_admin = db.scalar(
        select(User.id).where(User.is_system_admin.is_(True))
    )
    if existing_admin is not None:
        raise HTTPException(status_code=409, detail="A system administrator already exists.")

    validate_password(payload.password)

    user = create_user(
        db,
        email=payload.email,
        display_name=payload.display_name,
        password=payload.password,
        is_system_admin=True,
        must_change_password=True,
    )

    record_security_event(
        db,
        None,
        "system_admin_bootstrapped",
        user.id,
    )
    db.commit()
    db.refresh(user)

    return {
        "message": "Initial system administrator created successfully.",
        "user_id": user.id,
        "email": user.email,
    }


def authorize_request(request: Request, db: Session = Depends(get_db)) -> None:
    """Authenticate every API operation and enforce role plus institution scope."""
    path = request.url.path.removeprefix(get_settings().api_v1_prefix)
    method = request.method

    context = get_auth_context(request, db)
    request.state.auth_context = context

    if context.user.must_change_password and path not in {"/auth/session", "/auth/logout", "/auth/change-password"}:
        raise HTTPException(status_code=403, detail="Change the temporary password before using the workspace.")

    if path.startswith("/auth/users") or path.startswith("/auth/security-events"):
        require_system_admin(context)
        return
    if path in {"/auth/session", "/auth/logout", "/auth/change-password"}:
        return
    if path == "/institutions":
        if method == "POST":
            require_system_admin(context)
            return
        if method == "GET":
            # Allow authenticated users to list institutions (filtered by memberships in handler)
            return
    if path.startswith("/institutions/"):
        institution_id = request.path_params.get("institution_id")
        if not institution_id:
            raise HTTPException(status_code=404, detail="Resource was not found.")
        role = require_institution(context, institution_id)
        if method == "GET":
            return
        if method == "POST":
            if path.endswith("/fdr-records") and role in {"system_admin", "institution_admin"}:
                return
            if path.endswith("/transitions") and role in {"system_admin", "institution_admin", "approver", "reviewer"}:
                return
            if path.endswith("/documents") and role in {"system_admin", "institution_admin", "document_officer"}:
                return
            if path.endswith("/integrity-checks") and role in {"system_admin", "institution_admin", "document_officer", "reviewer", "approver"}:
                return
            if path.endswith("/relationships") and role in {"system_admin", "institution_admin", "reviewer"}:
                return
        raise HTTPException(status_code=403, detail="Your role does not permit this operation.")
    if path in {"/workflow/configuration", "/graph/policy", "/review-priority/policy", "/documents/policy"} and method == "GET":
        return
    raise HTTPException(status_code=403, detail="Your role does not permit this operation.")


router = APIRouter(dependencies=[Depends(authorize_request)])


def current_auth(request: Request) -> AuthContext:
    return request.state.auth_context


def user_response(db: Session, user: User) -> dict:
    memberships = list(db.scalars(select(InstitutionMembership).where(InstitutionMembership.user_id == user.id)))
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "system_admin": user.is_system_admin,
        "active": user.is_active,
        "must_change_password": user.must_change_password,
        "memberships": [{"institution_id": row.institution_id, "role": row.role} for row in memberships],
        "created_at": user.created_at,
    }


@public_router.get("/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    """Public liveness probe; it contains no institutional data."""
    return HealthResponse(status="ok")

@public_router.get("/public/institutions", response_model=list[InstitutionResponse], tags=["institutions"])
def public_list_institutions(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)) -> list[Institution]:
    """Public endpoint for unauthenticated institution list (used by sign‑up)."""
    return list(db.scalars(select(Institution).order_by(Institution.created_at.desc(), Institution.id).limit(limit)))

# Public user registration (self‑service sign‑up)
@public_router.post("/auth/register", response_model=AuthSessionResponse, status_code=201, tags=["authentication"])
def register_user(payload: UserRegistrationRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    # Ensure system_admin cannot be assigned
    if payload.role not in {"institution_admin", "document_officer", "reviewer", "approver", "auditor"}:
        raise HTTPException(status_code=422, detail="Invalid role specified.")
    if payload.institution_id and db.get(Institution, payload.institution_id) is None:
        raise HTTPException(status_code=404, detail="Institution not found.")

    # Create active user with no forced temporary password change for immediate dashboard access
    user = create_user(
        db,
        email=payload.email,
        display_name=payload.display_name,
        password=payload.password,
        is_system_admin=False,
        must_change_password=False,
    )
    user.is_active = True
    if payload.institution_id:
        db.add(InstitutionMembership(user_id=user.id, institution_id=payload.institution_id, role=payload.role))

    # Record registration event (public, no actor)
    record_security_event(db, None, "user_registered", user.id, {"role": payload.role, "institution_id": payload.institution_id})
    db.commit()
    db.refresh(user)

    # Establish authenticated session immediately
    context, token, csrf_token = authenticate(db, request, payload.email, payload.password)
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE, token, max_age=settings.auth_session_minutes * 60,
        httponly=True, secure=settings.auth_cookie_secure, samesite="strict", path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf_token, max_age=settings.auth_session_minutes * 60,
        httponly=False, secure=settings.auth_cookie_secure, samesite="strict", path="/",
    )
    return {"user": user_response(db, context.user), "csrf_token": csrf_token}


@public_router.post("/auth/login", response_model=AuthSessionResponse, tags=["authentication"])
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    context, token, csrf_token = authenticate(db, request, payload.email, payload.password)
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE, token, max_age=settings.auth_session_minutes * 60,
        httponly=True, secure=settings.auth_cookie_secure, samesite="strict", path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf_token, max_age=settings.auth_session_minutes * 60,
        httponly=False, secure=settings.auth_cookie_secure, samesite="strict", path="/",
    )
    return {"user": user_response(db, context.user), "csrf_token": csrf_token}


@router.get("/auth/session", response_model=AuthSessionResponse, tags=["authentication"])
def read_session(request: Request, db: Session = Depends(get_db)) -> dict:
    context = current_auth(request)
    csrf_token = request.cookies.get(CSRF_COOKIE, "")
    import secrets
    if not csrf_token or not secrets.compare_digest(hash_secret(csrf_token), context.session.csrf_hash):
        raise HTTPException(status_code=401, detail="Session is invalid or has expired. Sign in again.")
    return {"user": user_response(db, context.user), "csrf_token": csrf_token}


@router.post("/auth/logout", status_code=204, tags=["authentication"])
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    context = current_auth(request)
    context.session.revoked_at = utc_now()
    record_security_event(db, context.user.id, "logout")
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="strict")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/auth/change-password", status_code=204, tags=["authentication"])
def change_password(payload: ChangePasswordRequest, request: Request, db: Session = Depends(get_db)) -> Response:
    context = current_auth(request)
    try:
        password_hasher.verify(context.user.password_hash, payload.current_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        raise HTTPException(status_code=400, detail="Current password is incorrect.") from None
    validate_password(payload.new_password)
    context.user.password_hash = password_hasher.hash(payload.new_password)
    context.user.must_change_password = False
    for other in db.scalars(select(AuthSession).where(AuthSession.user_id == context.user.id, AuthSession.revoked_at.is_(None), AuthSession.token_hash != context.session.token_hash)):
        other.revoked_at = utc_now()
    record_security_event(db, context.user.id, "password_changed")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/auth/users", response_model=list[UserResponse], tags=["user-management"])
def list_users(db: Session = Depends(get_db), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
    users = db.scalars(select(User).order_by(User.created_at.desc(), User.id).limit(limit))
    return [user_response(db, user) for user in users]


@router.post("/auth/users", response_model=UserResponse, status_code=201, tags=["user-management"])
def provision_user(payload: UserProvisionRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    if (payload.institution_id is None) != (payload.role is None):
        raise HTTPException(status_code=422, detail="Institution ID and role must be provided together.")
    if payload.institution_id and db.get(Institution, payload.institution_id) is None:
        raise HTTPException(status_code=404, detail="Institution was not found.")
    user = create_user(
        db, email=payload.email, display_name=payload.display_name,
        password=payload.temporary_password, is_system_admin=payload.system_admin,
        must_change_password=True,
    )
    if payload.institution_id and payload.role:
        db.add(InstitutionMembership(user_id=user.id, institution_id=payload.institution_id, role=payload.role))
    context = current_auth(request)
    record_security_event(db, context.user.id, "user_provisioned", user.id, {"system_admin": payload.system_admin, "role": payload.role})
    db.commit()
    db.refresh(user)
    return user_response(db, user)


@router.put("/auth/users/{user_id}/memberships", response_model=UserResponse, tags=["user-management"])
def assign_membership(user_id: str, payload: MembershipRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None or db.get(Institution, payload.institution_id) is None:
        raise HTTPException(status_code=404, detail="User or institution was not found.")
    membership = db.scalar(select(InstitutionMembership).where(
        InstitutionMembership.user_id == user_id, InstitutionMembership.institution_id == payload.institution_id,
    ))
    if membership is None:
        membership = InstitutionMembership(user_id=user_id, institution_id=payload.institution_id, role=payload.role)
        db.add(membership)
    else:
        membership.role = payload.role
    context = current_auth(request)
    record_security_event(db, context.user.id, "membership_assigned", user_id, {"institution_id": payload.institution_id, "role": payload.role})
    db.commit()
    return user_response(db, user)


@router.patch("/auth/users/{user_id}/active", response_model=UserResponse, tags=["user-management"])
def set_user_active(user_id: str, payload: ActiveStateRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User was not found.")
    context = current_auth(request)
    if user.id == context.user.id and not payload.active:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own active session.")
    active_admin_count = db.scalar(select(func.count(User.id)).where(User.is_system_admin.is_(True), User.is_active.is_(True))) or 0
    if user.is_system_admin and user.is_active and not payload.active and active_admin_count <= 1:
        raise HTTPException(status_code=409, detail="The last active system administrator cannot be deactivated.")
    user.is_active = payload.active
    if not payload.active:
        for session in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))):
            session.revoked_at = utc_now()
    record_security_event(db, context.user.id, "user_activated" if payload.active else "user_deactivated", user_id)
    db.commit()
    return user_response(db, user)


@router.post("/auth/users/{user_id}/password-reset", status_code=204, tags=["user-management"])
def reset_user_password(user_id: str, payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)) -> Response:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User was not found.")
    user.password_hash = password_hasher.hash(payload.temporary_password)
    user.must_change_password = True
    for session in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))):
        session.revoked_at = utc_now()
    context = current_auth(request)
    record_security_event(db, context.user.id, "password_reset", user_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/auth/security-events", tags=["user-management"])
def read_security_events(db: Session = Depends(get_db), limit: int = Query(default=100, ge=1, le=500)) -> list[dict]:
    rows = db.scalars(select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc()).limit(limit))
    return [{"id": row.id, "actor_user_id": row.actor_user_id, "event_type": row.event_type,
             "target_user_id": row.target_user_id, "details": row.details, "created_at": row.created_at} for row in rows]


@router.get(
    "/institutions/{institution_id}/dashboard-summary",
    response_model=DashboardSummaryResponse,
    tags=["dashboard"],
)
def read_dashboard_summary(
    institution_id: str,
    db: Session = Depends(get_db),
) -> dict:
    if db.scalar(select(Institution.id).where(Institution.id == institution_id)) is None:
        raise HTTPException(status_code=404, detail="Institution was not found.")
    stages = db.execute(
        select(FDRRecord.workflow_stage, func.count(FDRRecord.id))
        .where(FDRRecord.institution_id == institution_id)
        .group_by(FDRRecord.workflow_stage)
    ).all()
    checks = db.execute(
        select(EvidenceCheck.result_status, func.count(EvidenceCheck.id))
        .where(EvidenceCheck.institution_id == institution_id)
        .group_by(EvidenceCheck.result_status)
    ).all()
    activity = list(db.scalars(
        select(AuditEvent)
        .where(AuditEvent.institution_id == institution_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(10)
    ))
    return {
        "institution_id": institution_id,
        "total_records": sum(count for _, count in stages),
        "stage_counts": {stage: count for stage, count in stages},
        "document_count": db.scalar(select(func.count(FDRDocument.id)).where(FDRDocument.institution_id == institution_id)) or 0,
        "integrity_check_counts": {status: count for status, count in checks},
        "recent_activity": activity,
    }


def get_workflow_service() -> WorkflowService:
    return WorkflowService(get_settings().workflow_config_path)


def get_document_service() -> DocumentService:
    settings = get_settings()
    return DocumentService(
        storage=PrivateLocalStorage(settings.private_storage_path),
        policy_loader=UploadPolicyLoader(settings.upload_policy_path),
        workflow=WorkflowService(settings.workflow_config_path),
    )


def get_graph_service() -> GraphService:
    return GraphService(get_settings().graph_policy_path)


def get_priority_service() -> PriorityScoringService:
    settings = get_settings()
    return PriorityScoringService(
        settings.priority_policy_path,
        WorkflowService(settings.workflow_config_path),
    )


@router.get("/workflow/configuration", response_model=WorkflowConfigurationResponse, tags=["workflow"])
def read_workflow_configuration(
    workflow: WorkflowService = Depends(get_workflow_service),
) -> WorkflowConfigurationResponse:
    return WorkflowConfigurationResponse(config=workflow.load_configuration())


@router.post(
    "/institutions",
    response_model=InstitutionResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["institutions"],
)
def create_institution(payload: InstitutionCreate, request: Request, db: Session = Depends(get_db)) -> Institution:
    actor = current_auth(request).user.id
    institution = Institution(name=payload.name)
    try:
        db.add(institution)
        db.flush()
        db.add(
            AuditEvent(
                institution_id=institution.id,
                event_type="institution_created",
                actor_id=actor,
                details={},
            )
        )
        db.commit()
        db.refresh(institution)
        return institution
    except Exception:
        db.rollback()
        raise


@router.get(
    "/institutions",
    response_model=list[InstitutionResponse],
    tags=["institutions"],
)
def list_institutions(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[Institution]:
    context = current_auth(request)
    query = select(Institution)
    if not context.user.is_system_admin:
        query = query.where(Institution.id.in_(context.memberships.keys()))
    return list(db.scalars(query.order_by(Institution.created_at, Institution.id).limit(limit)))


@router.post(
    "/institutions/{institution_id}/fdr-records",
    response_model=FDRRecordResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["fdr-records"],
)
def create_fdr_record(
    institution_id: str,
    payload: FDRRecordCreate,
    request: Request,
    db: Session = Depends(get_db),
    workflow: WorkflowService = Depends(get_workflow_service),
) -> FDRRecord:
    try:
        return workflow.create_record(db, institution_id, payload.instrument_reference, current_auth(request).user.id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}",
    response_model=FDRRecordResponse,
    tags=["fdr-records"],
)
def read_fdr_record(
    institution_id: str,
    record_id: str,
    db: Session = Depends(get_db),
) -> FDRRecord:
    record = db.scalar(
        select(FDRRecord).where(
            FDRRecord.id == record_id,
            FDRRecord.institution_id == institution_id,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="FDR record was not found for this institution.")
    return record


@router.get(
    "/institutions/{institution_id}/fdr-records",
    response_model=list[FDRRecordResponse],
    tags=["fdr-records"],
)
def list_fdr_records(
    institution_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[FDRRecord]:
    institution_exists = db.scalar(select(Institution.id).where(Institution.id == institution_id))
    if institution_exists is None:
        raise HTTPException(status_code=404, detail="Institution was not found.")
    return list(db.scalars(
        select(FDRRecord)
        .where(FDRRecord.institution_id == institution_id)
        .order_by(FDRRecord.updated_at.desc(), FDRRecord.id)
        .limit(limit)
    ))


@router.post(
    "/institutions/{institution_id}/fdr-records/{record_id}/transitions",
    response_model=FDRRecordResponse,
    tags=["workflow"],
)
def request_workflow_transition(
    institution_id: str,
    record_id: str,
    payload: TransitionRequest,
    request: Request,
    db: Session = Depends(get_db),
    workflow: WorkflowService = Depends(get_workflow_service),
) -> FDRRecord:
    context = current_auth(request)
    role = require_institution(context, institution_id)
    config = workflow.load_configuration()
    if role == "reviewer" and payload.target_stage not in config.clarification_stages:
        raise HTTPException(status_code=403, detail="Reviewers may only request a configured clarification stage.")
    if role == "approver" and payload.target_stage not in config.decision_stages:
        raise HTTPException(status_code=403, detail="Approvers may only transition records to configured decision stages.")
    if role == "institution_admin" and payload.target_stage in config.decision_stages:
        raise HTTPException(status_code=403, detail="Only an approver or system administrator may record a configured decision.")
    try:
        return workflow.transition(
            db,
            institution_id,
            record_id,
            payload.target_stage,
            current_auth(request).user.id,
            payload.reason,
        )
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/audit-events",
    response_model=list[AuditEventResponse],
    tags=["audit"],
)
def read_record_audit_history(
    institution_id: str,
    record_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[AuditEvent]:
    record_exists = db.scalar(
        select(FDRRecord.id).where(
            FDRRecord.id == record_id,
            FDRRecord.institution_id == institution_id,
        )
    )
    if record_exists is None:
        raise HTTPException(status_code=404, detail="FDR record was not found for this institution.")
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.institution_id == institution_id, AuditEvent.fdr_record_id == record_id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
        )
    )


@router.post(
    "/institutions/{institution_id}/fdr-records/{record_id}/documents",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["documents"],
)
async def upload_fdr_document(
    institution_id: str,
    record_id: str,
    request: Request,
    file: UploadFile = File(...),
    category_key: str = Form(..., min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$"),
    actor_id: str = Form(..., min_length=1, max_length=120),
    document_id: str | None = Form(default=None, max_length=36),
    db: Session = Depends(get_db),
    documents: DocumentService = Depends(get_document_service),
) -> DocumentResponse:
    try:
        return await documents.upload_async(
            db,
            institution_id,
            record_id,
            category_key.strip(),
            current_auth(request).user.id,
            file,
            document_id,
        )
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DocumentCategoryNotConfigured as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DocumentVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except UploadRejected as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/documents",
    response_model=list[DocumentResponse],
    tags=["documents"],
)
def list_fdr_documents(
    institution_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    documents: DocumentService = Depends(get_document_service),
) -> list[DocumentResponse]:
    try:
        return documents.list_documents(db, institution_id, record_id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/documents/{document_id}/versions",
    response_model=list[DocumentVersionResponse],
    tags=["documents"],
)
def list_fdr_document_versions(
    institution_id: str,
    record_id: str,
    document_id: str,
    db: Session = Depends(get_db),
    documents: DocumentService = Depends(get_document_service),
) -> list[DocumentVersionResponse]:
    try:
        return documents.list_versions(db, institution_id, record_id, document_id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/institutions/{institution_id}/fdr-records/{record_id}/documents/{document_id}/versions/{version_id}/integrity-checks",
    response_model=EvidenceCheckResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["evidence"],
)
def check_fdr_document_integrity(
    institution_id: str,
    record_id: str,
    document_id: str,
    version_id: str,
    payload: IntegrityCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
    documents: DocumentService = Depends(get_document_service),
) -> EvidenceCheckResponse:
    try:
        return documents.check_integrity(
            db,
            institution_id,
            record_id,
            document_id,
            version_id,
            current_auth(request).user.id,
        )
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/evidence-checks",
    response_model=list[EvidenceCheckResponse],
    tags=["evidence"],
)
def list_fdr_evidence_checks(
    institution_id: str,
    record_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    documents: DocumentService = Depends(get_document_service),
) -> list[EvidenceCheckResponse]:
    try:
        return documents.list_evidence_checks(db, institution_id, record_id, limit)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/graph/policy", response_model=GraphPolicyResponse, tags=["relationship-graph"])
def read_graph_policy(
    graph: GraphService = Depends(get_graph_service),
) -> GraphPolicyResponse:
    return graph.policy_response()


@router.get("/documents/policy", response_model=UploadPolicyResponse, tags=["documents"])
def read_upload_policy() -> UploadPolicyResponse:
    loader = UploadPolicyLoader(get_settings().upload_policy_path)
    policy = loader.load()
    return UploadPolicyResponse(policy=policy, policy_digest=loader.digest(policy))


@router.post(
    "/institutions/{institution_id}/fdr-records/{record_id}/relationships",
    response_model=RelationshipResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["relationship-graph"],
)
def create_fdr_relationship(
    institution_id: str,
    record_id: str,
    payload: RelationshipCreate,
    request: Request,
    db: Session = Depends(get_db),
    graph: GraphService = Depends(get_graph_service),
) -> RelationshipResponse:
    try:
        return graph.create_relationship(
            db, institution_id, record_id, payload.target_record_id,
            payload.relationship_type, payload.review_status, payload.note, current_auth(request).user.id,
        )
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidRelationship as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RelationshipConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/relationships",
    response_model=list[RelationshipResponse],
    tags=["relationship-graph"],
)
def list_fdr_relationships(
    institution_id: str,
    record_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    graph: GraphService = Depends(get_graph_service),
) -> list[RelationshipResponse]:
    try:
        return graph.list_relationships(db, institution_id, record_id, limit)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/graph",
    response_model=TraversalResponse,
    tags=["relationship-graph"],
)
def read_fdr_graph(
    institution_id: str,
    record_id: str,
    algorithm: str = Query(default="BFS", pattern="^(BFS|DFS)$"),
    max_depth: int | None = Query(default=None, ge=0, le=12),
    db: Session = Depends(get_db),
    graph: GraphService = Depends(get_graph_service),
) -> TraversalResponse:
    try:
        return graph.traverse(db, institution_id, record_id, algorithm, max_depth)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidRelationship as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/graph/bfs",
    response_model=TraversalResponse,
    tags=["relationship-graph"],
)
def traverse_fdr_graph_bfs(
    institution_id: str,
    record_id: str,
    max_depth: int | None = Query(default=None, ge=0, le=12),
    db: Session = Depends(get_db),
    graph: GraphService = Depends(get_graph_service),
) -> TraversalResponse:
    try:
        return graph.traverse(db, institution_id, record_id, "BFS", max_depth)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidRelationship as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/graph/dfs",
    response_model=TraversalResponse,
    tags=["relationship-graph"],
)
def traverse_fdr_graph_dfs(
    institution_id: str,
    record_id: str,
    max_depth: int | None = Query(default=None, ge=0, le=12),
    db: Session = Depends(get_db),
    graph: GraphService = Depends(get_graph_service),
) -> TraversalResponse:
    try:
        return graph.traverse(db, institution_id, record_id, "DFS", max_depth)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidRelationship as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/review-priority/policy",
    response_model=PriorityPolicyResponse,
    tags=["review-priority"],
)
def read_review_priority_policy(
    db: Session = Depends(get_db),
    priority: PriorityScoringService = Depends(get_priority_service),
) -> PriorityPolicyResponse:
    return priority.policy_response(db)


@router.get(
    "/institutions/{institution_id}/review-priority-queue",
    response_model=PriorityQueueResponse,
    tags=["review-priority"],
)
def read_review_priority_queue(
    institution_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    priority: PriorityScoringService = Depends(get_priority_service),
) -> PriorityQueueResponse:
    try:
        return priority.priority_queue(db, institution_id, limit)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/institutions/{institution_id}/fdr-records/{record_id}/urgency-score",
    response_model=UrgencyScoreResponse,
    tags=["review-priority"],
)
def calculate_fdr_urgency_score(
    institution_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    priority: PriorityScoringService = Depends(get_priority_service),
) -> UrgencyScoreResponse:
    try:
        return priority.calculate_record(db, institution_id, record_id)
    except EntityNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
