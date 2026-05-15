# Custom Authentication System

Backend-приложение реализует собственную систему аутентификации и авторизации без готовых framework-механизмов пользователей, сессий и permission-классов. Ядро вынесено в framework-agnostic backend (`CustomAuthBackend`), поэтому его можно запускать как небольшой WSGI-сервер для демонстрации или подключать к FastAPI почти как встроенную библиотеку через middleware и dependencies.

## Запуск демо без внешних зависимостей

```bash
python -m unittest discover -v
python -m custom_auth.app
```

Сервер стартует на `http://127.0.0.1:8000` и автоматически создаст локальную БД `custom_auth.sqlite3` с тестовыми данными.

## Подключение к FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from custom_auth.backend import AuthenticatedUser, CustomAuthBackend
from custom_auth.fastapi import (
    CustomAuthMiddleware,
    CurrentUser,
    admin_dependency,
    permission_dependency,
)

backend = CustomAuthBackend.with_sqlite("custom_auth.sqlite3")
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

Middleware читает `Authorization: Bearer <token>`, кладет найденного пользователя в `request.state.user`, а dependency helpers возвращают `401`, если пользователь не определен, и `403`, если прав недостаточно.

## Демо-пользователи

| Email | Password | Роль |
| --- | --- | --- |
| `admin@example.com` | `AdminPass123!` | `admin` |
| `user@example.com` | `UserPass123!` | `user` |

## Схема собственной системы доступа

### Таблицы пользователей и сессий

- `users` — собственная таблица пользователей: email, ФИО, PBKDF2-хэш пароля, `is_active`, timestamp мягкого удаления.
- `auth_sessions` — собственные bearer-сессии. Клиент получает случайный токен после login, а в БД хранится только SHA-256 хэш токена, срок действия, дата последнего использования и дата отзыва.
- При logout текущая сессия получает `revoked_at`.
- При мягком удалении аккаунта пользователь остается в таблице, но `is_active=0`; все его активные сессии отзываются, поэтому повторный login невозможен.

### Таблицы авторизации

- `roles` — роли: `admin`, `user`, `analyst`.
- `user_roles` — связь пользователей и ролей.
- `resources` — защищаемые ресурсы: `documents`, `reports`, `admin-dashboard`.
- `actions` — действия, сейчас создано действие `read`.
- `access_rules` — правило вида `role + resource + action -> is_allowed`.

Алгоритм проверки доступа:

1. Приложение читает `Authorization: Bearer <token>`.
2. Токен хэшируется SHA-256, по хэшу ищется активная и не истекшая `auth_sessions`.
3. Если пользователь не найден или `is_active=0`, endpoint возвращает `401`.
4. Если пользователь найден, но ни одна из его ролей не имеет разрешающего правила `access_rules`, endpoint возвращает `403`.
5. Если правило найдено, mock-view возвращает запрошенный ресурс.

## API демо-приложения

### Пользовательские операции

- `POST /api/auth/register/` — регистрация. Тело: `email`, `first_name`, `last_name`, `middle_name`, `password`, `password_repeat`.
- `POST /api/auth/login/` — вход по email и паролю, возвращает bearer-токен.
- `POST /api/auth/logout/` — выход, отзывает текущий токен.
- `GET /api/users/me/` — профиль текущего пользователя.
- `PATCH /api/users/me/` — обновление `first_name`, `last_name`, `middle_name`.
- `DELETE /api/users/me/delete/` — мягкое удаление аккаунта.

### Администрирование правил доступа

Доступно только пользователю с ролью `admin`:

- `GET /api/access/rules/` — список правил.
- `POST /api/access/rules/` — создать или обновить правило. Тело: `role`, `resource`, `action`, `is_allowed`.

### Mock-объекты бизнес-приложения

Таблицы для этих объектов не создаются; views возвращают вымышленные данные после проверки прав:

- `GET /api/business/documents/` — требует `documents:read`.
- `GET /api/business/reports/` — требует `reports:read`.
- `GET /api/business/admin-dashboard/` — требует `admin-dashboard:read`.
