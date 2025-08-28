# routes/fcm.py
import os, json, requests, logging
from flask import Blueprint, request, jsonify, make_response
from sqlalchemy import text

from models.table_fcm import db, FcmToken

log = logging.getLogger("fcm")

# ── 환경 변수 (필수)
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")  # service account JSON 경로
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "")                    # Firebase/GCP 프로젝트 ID

# (선택) 쿠키/세션 관련 – 기존 흐름 유지
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".guard-force.net")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1") == "1"

fcm_bp = Blueprint("fcm", __name__, url_prefix="/")

def _mask(t: str | None) -> str:
    if not t:
        return "-"
    return t if len(t) <= 12 else f"{t[:8]}...{t[-4:]}"

# ─────────────────────────────────────────────
# FCM v1 액세스 토큰 발급
# ─────────────────────────────────────────────
def _get_v1_access_token() -> str:
    assert GOOGLE_APPLICATION_CREDENTIALS, "GOOGLE_APPLICATION_CREDENTIALS not set"
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GoogleAuthRequest

    scopes = ["https://www.googleapis.com/auth/firebase.messaging"]
    credentials = service_account.Credentials.from_service_account_file(
        GOOGLE_APPLICATION_CREDENTIALS, scopes=scopes
    )
    log.info("_get_v1_access_token: credentials=%s", getattr(credentials, "service_account_email", "loaded"))
    credentials.refresh(GoogleAuthRequest())
    return credentials.token

# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────
def _cleanup_none(d):
    if isinstance(d, dict):
        return {k: _cleanup_none(v) for k, v in d.items() if v is not None}
    if isinstance(d, list):
        return [_cleanup_none(v) for v in d if v is not None]
    return d

# ─────────────────────────────────────────────
# v1 메시지 페이로드 빌더
# ─────────────────────────────────────────────
def build_v1_message(
    *,
    token: str,
    title: str | None = None,
    body: str | None = None,
    data: dict | None = None,
    # 공통 옵션
    ttl: str | None = None,              # 예: "3600s"
    collapse_key: str | None = None,
    # Android 옵션 (최소값만 – 정책은 앱이 결정)
    android: dict | None = None,         # 예: {"priority":"HIGH", "directBootOk": True}
    # iOS(APNs) 옵션 (기본은 None; 필요 시에만 명시적으로 사용)
    ios: dict | None = None,
    # WebPush 옵션 (옵션)
    webpush: dict | None = None,
    # 기본은 data-only (Android 자동 배너/사운드 방지)
    data_only: bool = True,
):
    """
    서버는 콘텐츠(title/body/data)만 전달하고, 알림 정책(일반/긴급/루프)은 앱이 결정.
    data_only=True:
      - 최상단 "notification" 제거 → Android FCM SDK 자동배너 방지(중복 팝업/사운드 X)
      - title/body를 data에도 복제(클라이언트가 로컬 알림/Heads-up에 활용)
    iOS:
      - 기본적으로 APNs alert를 넣지 않음(앱이 로컬 알림로 표현). 필요 시 ios 파라미터로 명시.
    """
    # 기본 data 병합 (title/body도 data로 복제)
    data = dict(data or {})
    if title is not None:
        data.setdefault("title", title)
    if body is not None:
        data.setdefault("body", body)

    msg = {
        "token": token,
        "data": data,  # Android는 data-only 처리
    }

    # Android block: 최소 설정 유지(정책은 앱에서)
    a_src = android or {}
    a = {
        "priority": a_src.get("priority") or "HIGH",
        "collapse_key": collapse_key,
        "ttl": ttl,
        "direct_boot_ok": a_src.get("directBootOk", True),
        "restricted_package_name": a_src.get("restrictedPackageName"),
        # channel_id/sound 등은 절대 넣지 않음(앱 정책과 충돌 방지)
    }
    msg["android"] = _cleanup_none(a)

    # APNs block (iOS) - 기본은 전송 안 함
    if ios:
        # background vs alert 자동 결정 (요청자 책임)
        content_available = bool(ios.get("contentAvailable"))
        apns_push_type = ios.get("apns-push-type") or ("background" if content_available else "alert")
        apns_priority = ios.get("apns-priority") or ("5" if apns_push_type == "background" else "10")

        # 주: 서버는 크리티컬/사운드 정책을 건드리지 않음. ios dict가 오면 그대로 사용.
        aps = {
            # data-only 전략이면 alert 생략 가능; 필요 시 호출자가 넣음
            "alert": ios.get("alert"),
            "sound": ios.get("sound"),
            "badge": ios.get("badge"),
            "content-available": 1 if content_available else None,
            "mutable-content": 1 if ios.get("mutableContent") else None,
            "interruption-level": ios.get("interruptionLevel"),
        }

        apns_headers = {
            "apns-push-type": apns_push_type,
            "apns-priority": apns_priority,
            "apns-topic": ios.get("apns-topic"),
        }

        msg["apns"] = _cleanup_none({
            "headers": apns_headers,
            "payload": {"aps": _cleanup_none(aps)},
        })

    # WebPush (옵션)
    if webpush:
        msg["webpush"] = _cleanup_none(webpush)

    # data_only=False 요청인 경우에만 상단 notification 사용(기본은 사용 안 함)
    if not data_only and (title or body):
        msg["notification"] = _cleanup_none({
            "title": title,
            "body": body,
        })

    payload = {"message": _cleanup_none(msg)}
    return payload

# ─────────────────────────────────────────────
# v1 전송
# ─────────────────────────────────────────────
def send_fcm_v1_message(payload: dict, dry_run: bool = False):
    assert FIREBASE_PROJECT_ID, "FIREBASE_PROJECT_ID must be set"
    access_token = _get_v1_access_token()

    url = f"https://fcm.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/messages:send"
    if dry_run:
        url += "?dry_run=true"

    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=payload, timeout=10)
    log.info("send_fcm_v1_message: status=%s body=%s", resp.status_code, resp.text)
    if resp.status_code >= 300:
        # FCM v1 에러 포맷 파싱 (UNREGISTERED 등)
        try:
            err = resp.json().get("error", {})
            status = err.get("status")
            details = err.get("details", [])
            fcm_err = None
            for d in details:
                if d.get("@type", "").endswith("google.firebase.fcm.v1.FcmError"):
                    fcm_err = d.get("errorCode")
                    break
            raise RuntimeError(f"FCM v1 error: {resp.status_code} status={status} fcm={fcm_err} msg={err.get('message')}")
        except Exception as e:
            raise RuntimeError(f"FCM v1 error: {resp.status_code} text={resp.text}") from e

    return resp.json()

def send_to_tokens_v1(tokens: list[str], *, title: str | None, body: str | None, data: dict | None,
                      android: dict | None = None, ios: dict | None = None, webpush: dict | None = None,
                      ttl: str | None = None, collapse_key: str | None = None, dry_run: bool = False, data_only: bool = True):
    if not tokens:
        return {"sent": 0, "results": []}

    results = []
    for tk in tokens:
        payload = build_v1_message(
            token=tk, title=title, body=body, data=data,
            android=android, ios=ios, webpush=webpush,
            ttl=ttl, collapse_key=collapse_key, data_only=data_only
        )
        try:
            res = send_fcm_v1_message(payload, dry_run=dry_run)
            results.append({"token": tk, "ok": True, "resp": res})
        except Exception as e:
            err_str = str(e)
            results.append({"token": tk, "ok": False, "error": err_str})
            # 토큰 무효화 자동 처리 (UNREGISTERED)
            if "UNREGISTERED" in err_str or "NOT_FOUND" in err_str:
                row = FcmToken.query.filter_by(token=tk).first()
                if row and row.active:
                    row.active = False
                    db.session.commit()
                    log.info("Token invalidated: %s", _mask(tk))
    return {"sent": len(tokens), "results": results}

def send_push_to_user(user_id: int, *, title: str | None, body: str | None, data: dict | None,
                      android: dict | None = None, ios: dict | None = None, webpush: dict | None = None,
                      ttl: str | None = None, collapse_key: str | None = None, dry_run: bool = False, data_only: bool = True):
    rows = FcmToken.query.filter_by(user_id=user_id, active=True).all()
    tokens = [r.token for r in rows]
    return send_to_tokens_v1(tokens, title=title, body=body, data=data,
                             android=android, ios=ios, webpush=webpush,
                             ttl=ttl, collapse_key=collapse_key, dry_run=dry_run, data_only=data_only)

# ─────────────────────────────────────────────
# 라우트
# ─────────────────────────────────────────────

@fcm_bp.route("/fcm/sync", methods=["POST", "OPTIONS"])
def fcm_sync():
    if request.method == "OPTIONS":
        return ("", 204)

    token = request.headers.get("X-FCM-Token") or (request.get_json(silent=True) or {}).get("token")
    platform = request.headers.get("X-Client-Platform", "webview")
    origin = request.headers.get("Origin")
    ua = request.headers.get("User-Agent")
    ip = request.get_json(silent=True) or request.headers.get("X-Forwarded-For", request.remote_addr)

    log.info("SYNC hdr ip=%s origin=%s token=%s ua=%s", ip, origin, _mask(token), ua)
    cur_db = db.session.execute(text("SELECT DATABASE()")).scalar()
    log.info("SYNC DB=%s token=%s platform=%s", cur_db, _mask(token), platform)

    if not token:
        log.warning("SYNC skipped: missing X-FCM-Token")
        return ("", 204)

    session_id = request.headers.get("X-Session-Id")  # 선택
    created, row_id = FcmToken.upsert_token(session_id=session_id, user_id=None, token=token, platform=platform)
    return jsonify({"ok": True, "created": created, "id": row_id})

@fcm_bp.route("/auth/attach", methods=["POST", "OPTIONS"])
def attach_tokens_to_user():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    hdr_token = request.headers.get("X-FCM-Token")
    session_id = request.headers.get("X-Session-Id")  # 선택

    updated = 0
    if hdr_token:
        row = FcmToken.query.filter_by(token=hdr_token).first()
        if row:
            row.user_id = user_id
            row.active = True
            db.session.commit()
            updated = 1
    elif session_id:
        rows = FcmToken.query.filter_by(session_id=session_id).all()
        for r in rows:
            r.user_id = user_id
            r.active = True
        db.session.commit()
        updated = len(rows)
    else:
        return jsonify({"error": "either X-FCM-Token or X-Session-Id header required"}), 400

    log.info("ATTACH user_id=%s updated=%s via=%s", user_id, updated, "token" if hdr_token else "session")
    return {"updated": updated}

@fcm_bp.route("/fcm/unregister", methods=["POST", "OPTIONS"])
def fcm_unregister():
    if request.method == "OPTIONS":
        return ("", 204)

    token = request.headers.get("X-FCM-Token") or request.cookies.get("fcm_token")
    if token:
        row = FcmToken.query.filter_by(token=token).first()
        if row:
            row.active = False
            db.session.commit()
            log.info("UNREGISTER token=%s -> inactive", _mask(token))

    resp = make_response("", 204)
    resp.delete_cookie("fcm_token", domain=COOKIE_DOMAIN, path="/")
    return resp

@fcm_bp.route("/event/notify", methods=["POST", "OPTIONS"])
def event_notify():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True)
    user_id = data.get("user_id")
    title = data.get("title", "Notification")
    body = data.get("body", "")
    custom_data = data.get("data", {}) or {}

    # ✅ 서버는 정책을 강제하지 않음: 안드로이드는 최소셋만
    android = data.get("android") or {"priority": "HIGH", "directBootOk": True}

    # ✅ iOS는 기본 전송 없음(필요 시 호출자가 명시적으로 넣을 때만 사용)
    ios = data.get("ios")  # 보통은 None 유지
    webpush = data.get("webpush")
    ttl = data.get("ttl")
    collapse_key = data.get("collapse_key")
    dry_run = bool(data.get("dry_run", False))
    data_only = bool(data.get("data_only", True))  # 기본 True

    if not user_id:
        log.warning("NOTIFY missing user_id; body=%s", data)
        return jsonify({"error": "user_id required"}), 400

    log.info("NOTIFY user_id=%s title=%s body=%s data=%s", user_id, title, body, custom_data)
    result = send_push_to_user(
        int(user_id),
        title=title, body=body, data=custom_data,
        android=android, ios=ios, webpush=webpush,
        ttl=ttl, collapse_key=collapse_key, dry_run=dry_run,
        data_only=data_only,
    )
    log.info("NOTIFY result sent=%s", result.get("sent"))
    return jsonify(result)

@fcm_bp.route("/fcm/send", methods=["POST", "OPTIONS"])
def fcm_send():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True)
    token = data.get("token")
    log.info("fcm_send token=%s", _mask(token))
    if not token:
        return jsonify({"error": "token required"}), 400

    title = data.get("title") or "알림"
    body = data.get("body") or ""
    custom_data = data.get("data") or {}

    android = data.get("android") or {"priority": "HIGH", "directBootOk": True}
    ios = data.get("ios")  # 기본 None
    webpush = data.get("webpush")
    ttl = data.get("ttl")
    collapse_key = data.get("collapse_key")
    dry_run = bool(data.get("dry_run", False))
    data_only = bool(data.get("data_only", True))  # 기본 True

    payload = build_v1_message(
        token=token, title=title, body=body, data=custom_data,
        android=android, ios=ios, webpush=webpush,
        ttl=ttl, collapse_key=collapse_key, data_only=data_only,
    )

    log.info("FCM payload sent: %s", json.dumps(payload, indent=2))

    try:
        result = send_fcm_v1_message(payload, dry_run=dry_run)
        log.info("SEND to token=%s ok", _mask(token))
        return jsonify({"ok": True, "resp": result})
    except Exception as e:
        log.error("SEND error token=%s err=%s", _mask(token), e)
        return jsonify({"ok": False, "error": str(e)}), 500

@fcm_bp.route("/debug/cookies", methods=["GET", "OPTIONS"])
def debug_cookies():
    if request.method == "OPTIONS":
        return ("", 204)
    return jsonify({
        "cookies": {k: v for k, v in request.cookies.items()},
        "headers": {k: v for k, v in request.headers.items()},
    })
