from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing import Annotated

RoleName = Literal["institution_admin", "document_officer", "reviewer", "approver", "auditor"]
EmailField = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=254)]
PasswordField = Annotated[str, StringConstraints(min_length=6, max_length=128)]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailField
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    new_password: PasswordField


class UserProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailField
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
    temporary_password: PasswordField
    system_admin: bool = False
    institution_id: str | None = Field(default=None, max_length=36)
    role: RoleName | None = None


class MembershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    institution_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=36)]
    role: RoleName


class ActiveStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool


class PasswordResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    temporary_password: PasswordField


class MembershipResponse(BaseModel):
    institution_id: str
    role: str


class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    system_admin: bool
    active: bool
    must_change_password: bool
    memberships: list[MembershipResponse]
    created_at: datetime


class AuthSessionResponse(BaseModel):
    user: UserResponse
    csrf_token: str

# Registration schemas

class UserRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailField
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
    password: PasswordField
    role: RoleName
    institution_id: str | None = Field(default=None, max_length=36)

class UserRegistrationResponse(UserResponse):
    pass

class BootstrapAdminRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailField
    display_name: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=120),
    ]
    password: PasswordField