from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MockResource:
    code: str
    action: str
    title: str
    description: str
    payload_key: str
    payload: Any


MOCK_RESOURCES: dict[str, MockResource] = {
    "documents": MockResource(
        code="documents",
        action="read",
        title="Документы",
        description="Доступен обычному пользователю с правилом documents:read.",
        payload_key="documents",
        payload=[
            {"id": 1, "title": "Public contract draft", "status": "draft"},
            {"id": 2, "title": "Partner onboarding checklist", "status": "review"},
        ],
    ),
    "reports": MockResource(
        code="reports",
        action="read",
        title="Отчёты",
        description="Показывает 403 для обычного user, пока admin не выдаст reports:read.",
        payload_key="reports",
        payload=[
            {"id": 1, "title": "Quarterly revenue report", "visibility": "analyst"},
            {"id": 2, "title": "Retention cohort analysis", "visibility": "analyst"},
        ],
    ),
    "admin-dashboard": MockResource(
        code="admin-dashboard",
        action="read",
        title="Admin dashboard",
        description="Доступен только роли admin по правилу admin-dashboard:read.",
        payload_key="metrics",
        payload={"active_users": 2, "access_rules": 6, "risk_level": "low"},
    ),
}


def list_mock_resources() -> list[dict[str, str]]:
    return [
        {
            "code": resource.code,
            "action": resource.action,
            "title": resource.title,
            "description": resource.description,
        }
        for resource in MOCK_RESOURCES.values()
    ]


def get_mock_resource(resource_code: str) -> MockResource | None:
    return MOCK_RESOURCES.get(resource_code)
