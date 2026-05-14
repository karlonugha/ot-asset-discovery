"""Initial database schema for OT Asset Discovery

Revision ID: 001
Revises: None
Create Date: 2024-01-01 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Devices table - core device inventory
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("mac_address", postgresql.MACADDR, nullable=False),
        sa.Column("ip_address", postgresql.INET, nullable=False),
        sa.Column("vendor", sa.String(128), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("firmware_version", sa.String(64), nullable=True),
        sa.Column("device_type", sa.String(50), nullable=True),
        sa.Column("protocols", postgresql.ARRAY(sa.Text), server_default="{}"),
        sa.Column("risk_score", sa.Integer, server_default="0"),
        sa.Column("fingerprint", postgresql.JSONB, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("mac_address", "ip_address", name="uq_devices_mac_ip"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_devices_risk_score"),
    )

    # Device history table - attribute change audit trail
    op.create_table(
        "device_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("field_name", sa.String(64), nullable=False),
        sa.Column("old_value", sa.Text, nullable=True),
        sa.Column("new_value", sa.Text, nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("idx_device_history_device_id", "device_history", ["device_id"])
    op.create_index("idx_device_history_changed_at", "device_history", [sa.text("changed_at DESC")])

    # Alerts table
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("details", postgresql.JSONB, nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("acknowledged", sa.Boolean, server_default="false"),
        sa.CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_alerts_severity"),
    )
    op.create_index("idx_alerts_severity", "alerts", ["severity"])
    op.create_index("idx_alerts_type", "alerts", ["alert_type"])
    op.create_index("idx_alerts_generated_at", "alerts", [sa.text("generated_at DESC")])
    op.create_index("idx_alerts_device_id", "alerts", ["device_id"])

    # Topology edges table
    op.create_table(
        "topology_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("source_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dest_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(30), nullable=False),
        sa.Column("packet_count", sa.BigInteger, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("source_device_id", "dest_device_id", "protocol", name="uq_topology_edges_src_dst_proto"),
    )
    op.create_index("idx_topology_source", "topology_edges", ["source_device_id"])
    op.create_index("idx_topology_dest", "topology_edges", ["dest_device_id"])

    # Scan jobs table
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("schedule", sa.String(64), nullable=True),
        sa.Column("target_subnet", postgresql.CIDR, nullable=True),
        sa.Column("active_probing_enabled", sa.Boolean, server_default="false"),
        sa.Column("status", sa.String(20), server_default="'scheduled'", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("devices_discovered", sa.Integer, server_default="0"),
        sa.Column("new_devices", sa.Integer, server_default="0"),
        sa.Column("alerts_generated", sa.Integer, server_default="0"),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )

    # Scan history table
    op.create_table(
        "scan_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("devices_discovered", sa.Integer, server_default="0"),
        sa.Column("new_devices", sa.Integer, server_default="0"),
        sa.Column("alerts_generated", sa.Integer, server_default="0"),
        sa.Column("failure_reason", sa.Text, nullable=True),
    )
    op.create_index("idx_scan_history_job_id", "scan_history", ["scan_job_id"])
    op.create_index("idx_scan_history_started_at", "scan_history", [sa.text("started_at DESC")])

    # Users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("username", sa.String(64), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("role", sa.String(20), server_default="'viewer'", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("role IN ('viewer', 'admin')", name="ck_users_role"),
    )

    # Auth attempts table - rate limiting
    op.create_table(
        "auth_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("ip_address", postgresql.INET, nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("success", sa.Boolean, server_default="false", nullable=False),
    )
    op.create_index("idx_auth_attempts_ip", "auth_attempts", ["ip_address", sa.text("attempted_at DESC")])


def downgrade() -> None:
    op.drop_table("auth_attempts")
    op.drop_table("users")
    op.drop_table("scan_history")
    op.drop_table("scan_jobs")
    op.drop_table("topology_edges")
    op.drop_table("alerts")
    op.drop_table("device_history")
    op.drop_table("devices")
