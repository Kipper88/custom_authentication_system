from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, status

from custom_auth.backend import CustomAuthBackend
from custom_auth.integrations.fastapi import CurrentUser, CustomAuthMiddleware, admin_dependency, permission_dependency
from custom_auth.services import AccessRuleError, AuthenticationError, ConflictError, ValidationError

backend = CustomAuthBackend.from_url("sqlite:///fastapi_demo.sqlite3")
app = FastAPI(title="Custom Auth FastAPI demo")
app.add_middleware(CustomAuthMiddleware, backend=backend)


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: dict[str, Any]):
    try:
        return {"user": backend.register(payload).as_dict()}
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@app.post("/auth/login")
def login(payload: dict[str, str]):
    try:
        result = backend.login(payload.get("email", ""), payload.get("password", ""))
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password") from exc
    return {"token": result.token, "user": result.user.as_dict()}


@app.post("/auth/logout")
def logout(user: CurrentUser):
    # The middleware already validated the token. The demo keeps logout simple;
    # production code can pass the raw token from a Request dependency.
    return {"status": "authenticated", "user": user.as_dict()}


@app.get("/users/me")
def me(user: CurrentUser):
    return {"user": user.as_dict()}


@app.patch("/users/me")
def update_me(payload: dict[str, str], user: CurrentUser):
    return {"user": backend.update_profile(user.id, payload).as_dict()}


@app.delete("/users/me")
def delete_me(user: CurrentUser):
    backend.soft_delete_user(user.id)
    return {"status": "deleted"}


@app.get("/access/rules")
def list_access_rules(user: Annotated[object, Depends(admin_dependency)]):
    return {"rules": backend.list_rules()}


@app.post("/access/rules", status_code=status.HTTP_201_CREATED)
def save_access_rule(payload: dict[str, Any], user: Annotated[object, Depends(admin_dependency)]):
    try:
        return {"rules": backend.save_rule(payload)}
    except AccessRuleError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.get("/business/documents")
def documents(user: Annotated[object, Depends(permission_dependency("documents"))]):
    return {"documents": [{"id": 1, "title": "Public contract draft"}]}


@app.get("/business/reports")
def reports(user: Annotated[object, Depends(permission_dependency("reports"))]):
    return {"reports": [{"id": 1, "title": "Quarterly revenue report"}]}
