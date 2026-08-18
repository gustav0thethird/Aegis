"""011 — Add scan_runs and scan_findings

Secret-scanner results reported by CI pipelines.

The matched credential is never persisted: secret_hash is a keyed HMAC used
only to recognise the same secret across scans, and secret_preview is masked.

Revision ID: 011
Revises: 010
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("team_id", UUID(as_uuid=True),
                  sa.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False),
        sa.Column("repository", sa.Text, nullable=False),
        sa.Column("ref", sa.Text),
        sa.Column("commit_sha", sa.Text),
        sa.Column("scanner", sa.Text, nullable=False),
        sa.Column("scanner_version", sa.Text),
        sa.Column("source", sa.Text),
        sa.Column("finding_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("new_finding_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_scan_runs_team_created", "scan_runs", ["team_id", "created_at"])
    op.create_index("ix_scan_runs_repository", "scan_runs", ["repository"])

    op.create_table(
        "scan_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        # Dedupe key: repository + rule + file + keyed secret hash.
        sa.Column("fingerprint", sa.Text, nullable=False),
        sa.Column("scan_run_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_runs.id", ondelete="SET NULL")),
        sa.Column("team_id", UUID(as_uuid=True),
                  sa.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False),

        sa.Column("repository", sa.Text, nullable=False),
        sa.Column("ref", sa.Text),
        sa.Column("commit_sha", sa.Text),
        sa.Column("scanner", sa.Text, nullable=False),
        sa.Column("rule_id", sa.Text),
        sa.Column("severity", sa.Text, nullable=False, server_default="medium"),
        sa.Column("title", sa.Text),
        sa.Column("description", sa.Text),
        sa.Column("file_path", sa.Text),
        sa.Column("line_start", sa.Integer),
        sa.Column("line_end", sa.Integer),
        # Never the credential itself.
        sa.Column("secret_hash", sa.Text),
        sa.Column("secret_preview", sa.Text),
        sa.Column("validated", sa.Boolean, nullable=False, server_default=sa.text("false")),

        sa.Column("status", sa.Text, nullable=False, server_default="open"),
        sa.Column("occurrences", sa.Integer, nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),

        sa.Column("ticket_key", sa.Text),
        sa.Column("ticket_url", sa.Text),
        sa.Column("alerted_at", sa.DateTime(timezone=True)),
        sa.Column("alert_error", sa.Text),

        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.Text),
    )
    # Unique so concurrent pipelines reporting the same leak converge on one row
    # rather than raising duplicate tickets.
    op.create_index("ix_scan_findings_fingerprint", "scan_findings",
                    ["fingerprint"], unique=True)
    op.create_index("ix_scan_findings_team_status", "scan_findings",
                    ["team_id", "status", "severity"])
    op.create_index("ix_scan_findings_repository", "scan_findings",
                    ["repository", "status"])


def downgrade():
    op.drop_index("ix_scan_findings_repository", table_name="scan_findings")
    op.drop_index("ix_scan_findings_team_status", table_name="scan_findings")
    op.drop_index("ix_scan_findings_fingerprint", table_name="scan_findings")
    op.drop_table("scan_findings")
    op.drop_index("ix_scan_runs_repository", table_name="scan_runs")
    op.drop_index("ix_scan_runs_team_created", table_name="scan_runs")
    op.drop_table("scan_runs")
