from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from api.models import AlertCreate, ChannelType, PlanTier, SubscribeRequest, UserResponse
from api.routers import alerts, analytics, billing, policies, realtime, rescan, scan, team, threat
from api.services import notifications


def _user(user_id: str = "user_1") -> UserResponse:
    return UserResponse(
        id=user_id,
        email=f"{user_id}@example.com",
        name="Test User",
        role="member",
        team_id="team_1",
        created_at=datetime.utcnow(),
    )


def _reviewer(user_id: str = "reviewer_1") -> UserResponse:
    user = _user(user_id)
    user.role = "reviewer"
    return user


def test_paid_subscription_fails_closed_without_stripe():
    mock_db = MagicMock()
    mock_db.upsert_subscription = AsyncMock()

    with (
        patch("api.routers.billing._get_stripe", return_value=None),
        patch(
            "api.routers.billing._get_or_create_subscription",
            AsyncMock(
                return_value={
                    "plan": "free",
                    "status": "active",
                    "stripe_customer_id": None,
                    "stripe_subscription_id": None,
                }
            ),
        ),
        patch("api.routers.billing.db", mock_db),
    ):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                billing.subscribe(
                    body=SubscribeRequest(plan=PlanTier.PRO, interval="monthly"),
                    current_user=_user(),
                )
            )

    assert exc.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    mock_db.upsert_subscription.assert_not_called()


def test_credit_purchase_fails_closed_without_stripe():
    with patch("api.routers.billing._get_stripe", return_value=None):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                billing.purchase_credits(
                    request=billing.PurchaseCreditsRequest(package_id=1),
                    current_user=_user(),
                    _=None,
                )
            )

    assert exc.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_webhook_processing_failure_returns_retryable_error(client: TestClient):
    payload = {"id": "evt_test", "type": "customer.subscription.updated", "data": {}}
    stripe = SimpleNamespace(
        Webhook=SimpleNamespace(
            construct_event=MagicMock(return_value=payload),
        ),
        error=SimpleNamespace(SignatureVerificationError=RuntimeError),
    )

    with (
        patch("api.routers.billing.settings.stripe_webhook_secret", "whsec_test"),
        patch("api.routers.billing._get_stripe", return_value=stripe),
        patch(
            "api.routers.billing._handle_subscription_updated",
            AsyncMock(side_effect=RuntimeError("database unavailable")),
        ),
    ):
        response = client.post("/v1/billing/webhook", json=payload)

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_unsigned_stripe_webhook_fails_closed_before_processing(client: TestClient):
    payload = {
        "id": "evt_unsigned",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_attacker",
                "subscription": "sub_attacker",
                "metadata": {"sigil_user_id": "user_1", "sigil_plan": "pro"},
            }
        },
    }

    with (
        patch("api.routers.billing.settings.stripe_webhook_secret", None),
        patch("api.routers.billing._get_stripe", return_value=None),
        patch("api.routers.billing._handle_checkout_completed", AsyncMock()) as handle,
    ):
        response = client.post("/v1/billing/webhook", json=payload)

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    handle.assert_not_awaited()


def test_billing_portal_fails_closed_without_stripe():
    with patch("api.routers.billing._get_stripe", return_value=None):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(billing.create_portal_session(current_user=_user()))

    assert exc.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_payment_failed_webhook_downgrade_failure_is_retryable():
    mock_db = MagicMock()
    mock_db.get_subscription_by_stripe_customer = AsyncMock(
        return_value={
            "user_id": "user_1",
            "plan": "pro",
            "stripe_customer_id": "cus_1",
            "current_period_end": "2099-01-01T00:00:00",
            "billing_interval": "monthly",
        }
    )
    mock_db.fetch_one = AsyncMock(return_value=None)
    mock_db.upsert_subscription = AsyncMock(side_effect=RuntimeError("db down"))
    mock_db.execute = AsyncMock()

    event = {
        "type": "invoice.payment_failed",
        "data": {
            "object": {
                "customer": "cus_1",
                "subscription": "sub_1",
                "amount_due": 2900,
                "attempt_count": 1,
            }
        },
    }

    with patch("api.routers.billing.db", mock_db):
        with pytest.raises(RuntimeError):
            asyncio.run(billing._handle_payment_failed(event))

    mock_db.execute.assert_not_awaited()


def test_payment_failed_webhook_removes_entitlement_but_preserves_paid_plan():
    mock_db = MagicMock()
    mock_db.get_subscription_by_stripe_customer = AsyncMock(
        return_value={
            "user_id": "user_1",
            "plan": "team",
            "stripe_customer_id": "cus_1",
            "current_period_end": "2099-01-01T00:00:00",
            "billing_interval": "monthly",
        }
    )
    mock_db.fetch_one = AsyncMock(return_value=None)
    mock_db.upsert_subscription = AsyncMock()
    mock_db.execute = AsyncMock()

    event = {
        "type": "invoice.payment_failed",
        "data": {
            "object": {
                "customer": "cus_1",
                "subscription": "sub_1",
                "amount_due": 2900,
                "attempt_count": 1,
            }
        },
    }

    with patch("api.routers.billing.db", mock_db):
        asyncio.run(billing._handle_payment_failed(event))

    mock_db.upsert_subscription.assert_awaited_once_with(
        user_id="user_1",
        plan="team",
        status="past_due",
        stripe_customer_id="cus_1",
        stripe_subscription_id="sub_1",
        current_period_end="2099-01-01T00:00:00",
        billing_interval="monthly",
    )
    mock_db.execute.assert_awaited_once()


def test_payment_succeeded_restore_failure_is_retryable():
    mock_db = MagicMock()
    mock_db.get_subscription_by_stripe_customer = AsyncMock(
        return_value={
            "user_id": "user_1",
            "plan": "pro",
            "status": "past_due",
            "stripe_customer_id": "cus_1",
            "current_period_end": "2099-01-01T00:00:00",
            "billing_interval": "monthly",
        }
    )
    mock_db.upsert_subscription = AsyncMock(side_effect=RuntimeError("db down"))
    mock_db.execute = AsyncMock()

    event = {
        "type": "invoice.payment_succeeded",
        "data": {
            "object": {
                "customer": "cus_1",
                "subscription": "sub_1",
                "amount_paid": 2900,
            }
        },
    }

    with patch("api.routers.billing.db", mock_db):
        with pytest.raises(RuntimeError):
            asyncio.run(billing._handle_payment_succeeded(event))

    mock_db.execute.assert_not_awaited()


def test_teamless_alert_user_cannot_share_default_team():
    user = _user()
    user.team_id = None

    with pytest.raises(HTTPException) as exc:
        asyncio.run(alerts.list_alerts(current_user=user, _=None))

    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc.value.detail == "Team membership required"


def test_teamless_policy_user_gets_user_scoped_namespace():
    user = _user("policy_user")
    user.team_id = None

    mock_db = MagicMock()
    mock_db.select = AsyncMock(return_value=[])

    with patch("api.routers.policies.db", mock_db):
        result = asyncio.run(
            policies.list_policies(current_user=user, _=None, enabled=None)
        )

    assert result == []
    mock_db.select.assert_awaited_once_with(
        "policies", {"team_id": "user:policy_user"}, limit=200
    )


def test_alert_webhook_rejects_private_destinations():
    request = AlertCreate(
        channel_type=ChannelType.WEBHOOK,
        channel_config={"webhook_url": "https://169.254.169.254/latest/meta-data"},
        enabled=True,
    )

    with pytest.raises(HTTPException) as exc:
        alerts._validate_channel_config(request.channel_type, request.channel_config)

    assert exc.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_webhook_delivery_rechecks_destination_before_posting():
    with patch("api.services.notifications.asyncio.open_connection") as connect:
        result = asyncio.run(
            notifications.send_webhook_notification(
                "https://169.254.169.254/latest/meta-data",
                {"event": "test"},
            )
        )

    assert result is False
    connect.assert_not_called()


def test_webhook_delivery_uses_resolved_public_ip_for_connection():
    class FakeReader:
        def __init__(self) -> None:
            self._lines = [b"HTTP/1.1 204 No Content\r\n", b"\r\n"]

        async def readline(self) -> bytes:
            return self._lines.pop(0) if self._lines else b""

        async def read(self, _limit: int) -> bytes:
            return b""

    writer = SimpleNamespace(
        write=MagicMock(),
        drain=AsyncMock(),
        close=MagicMock(),
        wait_closed=AsyncMock(),
    )

    async def fake_open_connection(*args, **kwargs):
        return FakeReader(), writer

    with (
        patch(
            "api.services.notifications.getaddrinfo",
            return_value=[
                (
                    0,
                    0,
                    0,
                    "",
                    ("93.184.216.34", 443),
                )
            ],
        ),
        patch(
            "api.services.notifications.asyncio.open_connection",
            side_effect=fake_open_connection,
        ) as connect,
    ):
        result = asyncio.run(
            notifications.send_webhook_notification(
                "https://webhook.example.com/path?token=abc",
                {"event": "test"},
            )
        )

    assert result is True
    connect.assert_awaited_once()
    assert connect.await_args.args[:2] == ("93.184.216.34", 443)
    assert connect.await_args.kwargs["server_hostname"] == "webhook.example.com"
    assert b"POST /path?token=abc HTTP/1.1" in writer.write.call_args.args[0]


def test_email_notification_does_not_reference_webhook_url_when_smtp_configured():
    with (
        patch("api.services.notifications.settings.smtp_host", "smtp.example.com"),
        patch("api.services.notifications.settings.smtp_user", "user"),
        patch("api.services.notifications.settings.smtp_password", "password"),
        patch("api.services.notifications.settings.smtp_from_email", "alerts@example.com"),
        patch("api.services.notifications._smtp_send", return_value=None) as smtp_send,
    ):
        result = asyncio.run(
            notifications.send_email_notification(
                ["owner@example.com"],
                "Subject",
                "Body",
            )
        )

    assert result is True
    smtp_send.assert_called_once()


def _team_user(user_id: str, role: str, team_id: str) -> UserResponse:
    return UserResponse(
        id=user_id,
        email=f"{user_id}@example.com",
        name=user_id,
        role=role,
        team_id=team_id,
        created_at=datetime.utcnow(),
    )


def test_team_invite_rejects_owner_role():
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            team.invite_member(
                body=team.TeamInviteRequest(email="new@example.com", role="owner"),
                current_user=_team_user("admin_1", "admin", "team_a"),
                _=None,
            )
        )

    assert exc.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_team_invite_cannot_take_existing_user_from_another_team():
    caller = _team_user("admin_1", "admin", "team_a")
    caller_row = {"id": "admin_1", "role": "admin", "team_id": "team_a"}
    team_row = {"id": "team_a", "owner_id": "owner_a", "name": "Team A"}
    existing = {
        "id": "victim_1",
        "email": "victim@example.com",
        "role": "member",
        "team_id": "team_b",
    }
    mock_db = MagicMock()
    mock_db.select_one = AsyncMock(side_effect=[caller_row, caller_row, team_row, existing])
    mock_db.upsert = AsyncMock()

    with patch("api.routers.team.db", mock_db):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                team.invite_member(
                    body=team.TeamInviteRequest(
                        email="victim@example.com", role="member"
                    ),
                    current_user=caller,
                    _=None,
                )
            )

    assert exc.value.status_code == status.HTTP_409_CONFLICT
    mock_db.upsert.assert_not_awaited()


def test_team_remove_cannot_clear_other_team_user():
    caller = _team_user("admin_1", "admin", "team_a")
    caller_row = {"id": "admin_1", "role": "admin", "team_id": "team_a"}
    target_row = {"id": "victim_1", "role": "member", "team_id": "team_b"}
    team_row = {"id": "team_a", "owner_id": "owner_a", "name": "Team A"}
    mock_db = MagicMock()
    mock_db.select_one = AsyncMock(side_effect=[caller_row, target_row, caller_row, team_row])
    mock_db.upsert = AsyncMock()

    with patch("api.routers.team.db", mock_db):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                team.remove_member(
                    user_id="victim_1",
                    current_user=caller,
                    _=None,
                )
            )

    assert exc.value.status_code == status.HTTP_404_NOT_FOUND
    mock_db.upsert.assert_not_awaited()


def test_websocket_rejects_missing_auth_before_accept():
    websocket = SimpleNamespace(query_params={}, headers={}, close=AsyncMock())

    result = asyncio.run(realtime.get_current_user_from_websocket(websocket))

    assert result is None
    websocket.close.assert_awaited_once_with(
        code=1008, reason="Authentication required"
    )


def test_websocket_rejects_user_id_mismatch_before_connect():
    websocket = SimpleNamespace(close=AsyncMock())

    with (
        patch(
            "api.routers.realtime.get_current_user_from_websocket",
            AsyncMock(return_value=_user("user_a")),
        ),
        patch(
            "api.routers.realtime.dashboard_service.connect_websocket",
            AsyncMock(),
        ) as connect_websocket,
    ):
        asyncio.run(realtime.websocket_dashboard(websocket, "user_b"))

    websocket.close.assert_awaited_once_with(code=1008, reason="User mismatch")
    connect_websocket.assert_not_awaited()


def test_pro_member_cannot_update_threat_report_status():
    with patch("api.routers.threat.update_report_status", AsyncMock()) as update:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                threat.update_report(
                    report_id="report_1",
                    body=threat.ReportStatusUpdate(status="confirmed"),
                    current_user=_user(),
                    _=None,
                )
            )

    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    update.assert_not_awaited()


def test_reviewer_can_update_threat_report_status():
    expected = {"id": "report_1", "status": "confirmed"}
    with patch(
        "api.routers.threat.update_report_status", AsyncMock(return_value=expected)
    ) as update:
        result = asyncio.run(
            threat.update_report(
                report_id="report_1",
                body=threat.ReportStatusUpdate(status="confirmed"),
                current_user=_reviewer(),
                _=None,
            )
        )

    assert result == expected
    update.assert_awaited_once()


def test_pro_member_cannot_approve_scan():
    with patch("api.routers.scan._get_user_scan_or_404", AsyncMock()) as get_scan:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                scan.approve_scan(scan_id="scan_1", current_user=_user(), _=None)
            )

    assert exc.value.status_code == status.HTTP_403_FORBIDDEN
    get_scan.assert_not_awaited()


def test_reviewer_can_approve_scan():
    row = {
        "id": "scan_1",
        "metadata_json": {},
    }
    mock_db = MagicMock()
    mock_db.upsert = AsyncMock()

    with (
        patch("api.routers.scan._get_user_scan_or_404", AsyncMock(return_value=row)),
        patch("api.routers.scan.db", mock_db),
    ):
        result = asyncio.run(
            scan.approve_scan(scan_id="scan_1", current_user=_reviewer(), _=None)
        )

    assert result["status"] == "approved"
    mock_db.upsert.assert_awaited_once()


def test_scan_detail_lookup_hides_other_tenant_scan():
    row = {
        "id": "scan_1",
        "user_id": "other_user",
        "team_id": "other_team",
        "metadata_json": {"user_id": "other_user", "team_id": "other_team"},
    }

    with patch("api.routers.scan._get_scan_or_404", AsyncMock(return_value=row)):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(scan._get_user_scan_or_404("scan_1", _user("user_1")))

    assert exc.value.status_code == status.HTTP_404_NOT_FOUND


def test_scan_detail_lookup_allows_owner_and_team_member():
    owner_row = {"id": "scan_1", "user_id": "user_1", "team_id": "team_2"}
    team_row = {"id": "scan_2", "user_id": "other_user", "team_id": "team_1"}

    with patch(
        "api.routers.scan._get_scan_or_404",
        AsyncMock(side_effect=[owner_row, team_row]),
    ) as get_scan:
        owner_result = asyncio.run(
            scan._get_user_scan_or_404("scan_1", _user("user_1"))
        )
        team_result = asyncio.run(
            scan._get_user_scan_or_404("scan_2", _user("user_1"))
        )

    assert owner_result == owner_row
    assert team_result == team_row
    assert get_scan.await_args_list == [call("scan_1"), call("scan_2")]


def test_rescan_record_access_is_tenant_scoped():
    user = _user("user_1")

    assert rescan._can_access_scan_record({"user_id": "user_1"}, user) is True
    assert rescan._can_access_scan_record({"team_id": "team_1"}, user) is True
    assert (
        rescan._can_access_scan_record(
            {"metadata_json": {"user_id": "user_1", "team_id": "team_2"}},
            user,
        )
        is True
    )
    assert (
        rescan._can_access_scan_record(
            {"user_id": "other", "team_id": "other_team"},
            user,
        )
        is False
    )


def test_rescan_rejects_other_tenant_before_mutating():
    row = {
        "id": "scan_1",
        "user_id": "other",
        "team_id": "other_team",
        "scanner_version": "1.0.0",
        "risk_score": 10.0,
        "verdict": "HIGH_RISK",
        "findings_json": [],
        "metadata_json": {},
    }
    mock_db = MagicMock()
    mock_db.select_one = AsyncMock(return_value=row)
    mock_db.update = AsyncMock()

    with patch("api.routers.rescan.db", mock_db):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(rescan.rescan_package("scan_1", _user("user_1")))

    assert exc.value.status_code == status.HTTP_404_NOT_FOUND
    mock_db.update.assert_not_awaited()


def test_enterprise_member_cannot_read_global_analytics():
    user = _user("enterprise_member")
    user.role = "member"

    with patch("api.routers.analytics.get_user_tier", AsyncMock(return_value=PlanTier.ENTERPRISE)):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(analytics.require_admin_tier(user))

    assert exc.value.status_code == status.HTTP_403_FORBIDDEN


def test_enterprise_admin_can_read_global_analytics():
    user = _user("enterprise_admin")
    user.role = "admin"

    with patch("api.routers.analytics.get_user_tier", AsyncMock(return_value=PlanTier.ENTERPRISE)):
        result = asyncio.run(analytics.require_admin_tier(user))

    assert result == user
