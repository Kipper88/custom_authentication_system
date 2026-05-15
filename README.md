# Custom Authentication System

Проект реализует собственную систему аутентификации и авторизации: пользователи, bearer-сессии, роли, ресурсы, действия и правила доступа описаны в нашей доменной модели, а не взяты из готового auth-модуля Django/FastAPI. Работа с БД вынесена в SQLAlchemy ORM, бизнес-правила — в сервисный слой, HTTP-интеграции — в отдельные demo-приложения.

## Архитектура

```text
custom_auth/
  models.py              # SQLAlchemy ORM модели: users, roles, resources, actions, access_rules, auth_sessions
  database.py            # engine/session factory, создание схемы, seed демо-данных
  repositories.py        # SQLAlchemy repository; единственное место с ORM-запросами
  services.py            # AuthService: регистрация, login/logout, soft-delete, RBAC-проверки
  backend.py             # фасад CustomAuthBackend с границами SQLAlchemy-сессий
  integrations/
    fastapi.py           # middleware + dependencies для FastAPI/Starlette
    drf.py               # authentication/permission classes для DRF
apps/
  fastapi_app/main.py    # тестовое FastAPI-приложение
  drf_app/               # тестовое DRF-приложение
```

Такое разделение позволяет использовать один и тот же сервис авторизации в разных web-фреймворках. Например, SQLite можно заменить на PostgreSQL через database URL, не переписывая правила доступа.

## Установка и запуск

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -v
```

### FastAPI demo

```bash
uvicorn apps.fastapi_app.main:app --reload
```

### DRF demo

```bash
export DJANGO_SETTINGS_MODULE=apps.drf_app.settings
python -m django runserver
```

## Демо-пользователи

Seed-данные создаются при инициализации `CustomAuthBackend`.

| Email | Password | Роль |
| --- | --- | --- |
| `admin@example.com` | `AdminPass123!` | `admin` |
| `user@example.com` | `UserPass123!` | `user` |

## Схема доступа

### Таблицы

- `users` — пользовательские аккаунты: email, ФИО, PBKDF2-хэш пароля, `is_active`, дата мягкого удаления.
- `auth_sessions` — bearer-сессии: хранится SHA-256-хэш токена, срок действия, дата последнего использования и дата отзыва.
- `roles` — роли (`admin`, `user`, `analyst`).
- `user_roles` — связь пользователей и ролей.
- `resources` — защищаемые ресурсы (`documents`, `reports`, `admin-dashboard`).
- `actions` — действия над ресурсами (`read`).
- `access_rules` — правило `role + resource + action -> is_allowed`.

### Алгоритм проверки

1. Интеграция читает `Authorization: Bearer <token>`.
2. `AuthService` хэширует токен и ищет активную, не отозванную, не истекшую `auth_sessions`.
3. Если пользователь не найден или `users.is_active=False`, возвращается `401`.
4. Если пользователь найден, но у его ролей нет разрешающего `access_rules`, возвращается `403`.
5. Если разрешение найдено, endpoint возвращает mock-ресурс.

## Использование в FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from custom_auth.backend import CustomAuthBackend
from custom_auth.integrations.fastapi import CustomAuthMiddleware, CurrentUser, admin_dependency, permission_dependency
from custom_auth.services import AuthenticatedUser

backend = CustomAuthBackend.from_url("sqlite:///custom_auth.sqlite3")
app = FastAPI()
app.add_middleware(CustomAuthMiddleware, backend=backend)


@app.get("/me")
def me(user: CurrentUser):
    return user.as_dict()


@app.get("/documents")
def documents(user: Annotated[AuthenticatedUser, Depends(permission_dependency("documents", "read"))]):
    return {"documents": [{"id": 1, "title": "Public contract draft"}]}


@app.get("/access-rules")
def access_rules(user: Annotated[AuthenticatedUser, Depends(admin_dependency)]):
    return {"rules": backend.list_rules()}
```

## Использование в DRF

```python
from rest_framework.views import APIView
from rest_framework.response import Response

from custom_auth.backend import CustomAuthBackend
from custom_auth.integrations.drf import as_authentication_class, require_permission

backend = CustomAuthBackend.from_url("sqlite:///custom_auth.sqlite3")
Authentication = as_authentication_class(backend)


class DocumentsView(APIView):
    auth_backend = backend
    authentication_classes = [Authentication]
    permission_classes = [require_permission("documents")]

    def get(self, request):
        return Response({"documents": [{"id": 1, "title": "Public contract draft"}]})
```

## API demo-приложений

- `POST /auth/register` — регистрация (`email`, `first_name`, `last_name`, `middle_name`, `password`, `password_repeat`).
- `POST /auth/login` — вход по email и паролю, возвращает bearer-токен.
- `GET /users/me`, `PATCH /users/me`, `DELETE /users/me` — профиль, обновление и мягкое удаление.
- `GET /access/rules`, `POST /access/rules` — просмотр и изменение правил администратором.
- `GET /business/documents`, `GET /business/reports` — mock-ресурсы с проверкой access rules.
