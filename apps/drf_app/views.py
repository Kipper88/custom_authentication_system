from __future__ import annotations

from typing import Any

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from custom_auth.backend import CustomAuthBackend
from custom_auth.integrations.drf import as_authentication_class, require_admin, require_permission, user_response
from custom_auth.services import AccessRuleError, AuthenticationError, ConflictError, ValidationError

backend = CustomAuthBackend.from_url("sqlite:///drf_demo.sqlite3")
Authentication = as_authentication_class(backend)


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            return Response({"user": backend.register(request.data).as_dict()}, status=status.HTTP_201_CREATED)
        except ValidationError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except ConflictError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)


class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            result = backend.login(request.data.get("email", ""), request.data.get("password", ""))
        except AuthenticationError:
            return Response({"detail": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({"token": result.token, "user": result.user.as_dict()})


class MeView(APIView):
    authentication_classes = [Authentication]

    def get(self, request):
        return Response({"user": user_response(request.custom_auth_user)})

    def patch(self, request):
        return Response({"user": backend.update_profile(request.custom_auth_user.id, request.data).as_dict()})

    def delete(self, request):
        backend.soft_delete_user(request.custom_auth_user.id)
        return Response({"status": "deleted"})


class AccessRulesView(APIView):
    auth_backend = backend
    authentication_classes = [Authentication]
    permission_classes = [require_admin()]

    def get(self, request):
        return Response({"rules": backend.list_rules()})

    def post(self, request):
        try:
            return Response({"rules": backend.save_rule(request.data)}, status=status.HTTP_201_CREATED)
        except AccessRuleError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class DocumentsView(APIView):
    auth_backend = backend
    authentication_classes = [Authentication]
    permission_classes = [require_permission("documents")]

    def get(self, request):
        return Response({"documents": [{"id": 1, "title": "Public contract draft"}]})


class ReportsView(APIView):
    auth_backend = backend
    authentication_classes = [Authentication]
    permission_classes = [require_permission("reports")]

    def get(self, request):
        return Response({"reports": [{"id": 1, "title": "Quarterly revenue report"}]})
