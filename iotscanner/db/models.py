"""SQLAlchemy ORM models for device storage."""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    mac: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    friendly_name: Mapped[str | None] = mapped_column(String, nullable=True)
    model_name: Mapped[str | None] = mapped_column(String, nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String, nullable=True)
    http_banner: Mapped[str | None] = mapped_column(String, nullable=True)
    services: Mapped[list | None] = mapped_column(JSON, nullable=True)
    open_ports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    upnp_location: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<Device {self.ip} ({self.mac})>"