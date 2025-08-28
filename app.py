# app.py
import os
from dotenv import load_dotenv
import logging

load_dotenv(dotenv_path="/home/ubuntu/guard-force-push-api/.env", override=True)

from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate

from models.table_fcm import db  # SQLAlchemy() 인스턴스
from routes.fcm import fcm_bp    # FCM 관련 블루프린트


def _mysql_uri_from_env() -> str:
    # DATABASE_URL이 있으면 우선 사용 (예: mysql+pymysql://user:pw@host:3306/db?charset=utf8mb4)
    url = os.getenv("DATABASE_URL")
    if url:
        print("[DB] Using DATABASE_URL")
        return url

    user = os.getenv("MYSQL_USER")
    pw = os.getenv("MYSQL_PASSWORD")
    host = os.getenv("MYSQL_HOST")
    port = os.getenv("MYSQL_PORT")
    dbname = os.getenv("MYSQL_DB")
    print(f"[DB] Using parts: user={user}, host={host}, port={port}, db={dbname}")

    return f"mysql+pymysql://{user}:{pw}@{host}:{port}/{dbname}?charset=utf8mb4"

def create_app():
    app = Flask(__name__)

    if not app.logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        ))
        app.logger.addHandler(h)

    app.logger.setLevel(logging.INFO)

    fcm_logger = logging.getLogger("fcm")
    fcm_logger.setLevel(logging.INFO)
    fcm_logger.handlers = app.logger.handlers
    fcm_logger.propagate = False   # 중복 출력 방지

    # ── CORS 설정: 다른 오리진(https://www.guard-force.net)에서 API 호출 허용
    # 환경변수 FRONTEND_ORIGIN으로 교체 가능 (기본값: https://www.guard-force.net)
    frontend_origin = os.getenv("FRONTEND_ORIGIN", "https://www.guard-force.net")

    CORS(
        app,
        resources={r"/api/*": {"origins": [frontend_origin]}},
        supports_credentials=False,  # 쿠키 사용 안 함(헤더로 토큰 전달)
        allow_headers=[
            "Content-Type",
            "X-FCM-Token",
            "X-Client-Platform",
            "X-Session-Id",
        ],
        methods=["GET", "POST", "OPTIONS"],
        max_age=86400,  # 프리플라이트 캐시(1일)
    )

    # ── DB 설정 (MySQL)
    app.config["SQLALCHEMY_DATABASE_URI"] = _mysql_uri_from_env()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # 선택: 커넥션 풀 옵션
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    db.init_app(app)
    Migrate(app, db)

    # 테이블 자동 생성(개발 편의). 운영에선 마이그레이션 사용 권장.
    if os.getenv("AUTO_CREATE_TABLES", "0") == "1":
        with app.app_context():
            db.create_all()

    # 블루프린트 등록
    app.register_blueprint(fcm_bp)

    # 헬스체크
    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app

app = create_app()

if __name__ == "__main__":
    # 개발 실행
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=True)
