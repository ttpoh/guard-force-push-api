# models/table_fcm.py
from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from sqlalchemy import UniqueConstraint

db = SQLAlchemy()

class FcmToken(db.Model):
    __tablename__ = "fcm_tokens"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=True, index=True)        # 로그인 전 None
    session_id = db.Column(db.String(128), nullable=True, index=True)    # 웹/앱 세션 등
    token      = db.Column(db.String(512), nullable=False)               # FCM 토큰 (길이 넉넉히)
    platform   = db.Column(db.String(20),  nullable=False, default="unknown", index=True)  # ios/android/webview 등
    active     = db.Column(db.Boolean,     nullable=False, default=True, index=True)

    # 생성/갱신 시각
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("token", name="uq_fcm_token"),  # token 유니크
    )

    @classmethod
    def upsert_token(cls, *, session_id: str | None, user_id: int | None, token: str, platform: str | None):
        """
        token 기준으로 Upsert. 생성 여부와 row.id 반환
        """
        assert token, "token is required"

        row = cls.query.filter_by(token=token).one_or_none()
        created = False

        if row is None:
            row = cls(
                session_id=session_id,
                user_id=user_id,
                token=token,
                platform=(platform or "unknown")[:20],
                active=True,
            )
            db.session.add(row)
            created = True
        else:
            # 필요한 필드만 갱신
            row.session_id = session_id or row.session_id
            row.user_id    = user_id if user_id is not None else row.user_id
            row.platform   = (platform or row.platform or "unknown")[:20]
            row.active     = True

        db.session.commit()
        return created, row.id

    def __repr__(self) -> str:
        head = self.token[:8] if self.token else "-"
        tail = self.token[-4:] if self.token else "-"
        return f"<FcmToken id={self.id} user_id={self.user_id} active={self.active} token={head}...{tail}>"
