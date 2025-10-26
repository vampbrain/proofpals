"""Initial migration for ProofPals database

Revision ID: 001_initial
Revises: 
Create Date: 2025-01-26 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create initial tables"""
    
    # Submissions table
    op.create_table('submissions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('genre', sa.String(length=50), nullable=False),
        sa.Column('content_ref', sa.String(length=255), nullable=False),
        sa.Column('submitter_ip_hash', sa.String(length=64), nullable=False),
        sa.Column('submitter_mac_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('last_tallied_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_submissions_id'), 'submissions', ['id'], unique=False)
    op.create_index(op.f('ix_submissions_genre'), 'submissions', ['genre'], unique=False)
    op.create_index(op.f('ix_submissions_status'), 'submissions', ['status'], unique=False)
    
    # Rings table
    op.create_table('rings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('genre', sa.String(length=50), nullable=False),
        sa.Column('pubkeys', sa.JSON(), nullable=False),
        sa.Column('epoch', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_rings_id'), 'rings', ['id'], unique=False)
    op.create_index(op.f('ix_rings_genre'), 'rings', ['genre'], unique=False)
    op.create_index(op.f('ix_rings_epoch'), 'rings', ['epoch'], unique=False)
    op.create_index(op.f('ix_rings_active'), 'rings', ['active'], unique=False)
    op.create_index('ix_rings_genre_epoch', 'rings', ['genre', 'epoch'], unique=False)
    op.create_index('ix_rings_active_epoch', 'rings', ['active', 'epoch'], unique=False)
    
    # Reviewers table
    op.create_table('reviewers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('profile_hash', sa.String(length=64), nullable=True),
        sa.Column('credential_meta', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('revoked_bool', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reviewers_id'), 'reviewers', ['id'], unique=False)
    op.create_index(op.f('ix_reviewers_profile_hash'), 'reviewers', ['profile_hash'], unique=False)
    op.create_index(op.f('ix_reviewers_revoked_bool'), 'reviewers', ['revoked_bool'], unique=False)
    
    # Votes table
    op.create_table('votes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('submission_id', sa.Integer(), nullable=False),
        sa.Column('ring_id', sa.Integer(), nullable=False),
        sa.Column('signature_blob', sa.Text(), nullable=False),
        sa.Column('key_image', sa.String(length=64), nullable=False),
        sa.Column('vote_type', sa.String(length=20), nullable=False),
        sa.Column('token_id', sa.String(length=64), nullable=False),
        sa.Column('verified_bool', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['ring_id'], ['rings.id'], ),
        sa.ForeignKeyConstraint(['submission_id'], ['submissions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_votes_id'), 'votes', ['id'], unique=False)
    op.create_index(op.f('ix_votes_submission_id'), 'votes', ['submission_id'], unique=False)
    op.create_index(op.f('ix_votes_ring_id'), 'votes', ['ring_id'], unique=False)
    op.create_index(op.f('ix_votes_key_image'), 'votes', ['key_image'], unique=False)
    op.create_index(op.f('ix_votes_vote_type'), 'votes', ['vote_type'], unique=False)
    op.create_index(op.f('ix_votes_token_id'), 'votes', ['token_id'], unique=False)
    op.create_index(op.f('ix_votes_verified_bool'), 'votes', ['verified_bool'], unique=False)
    op.create_index('ix_votes_submission_key_image', 'votes', ['submission_id', 'key_image'], unique=False)
    op.create_index('ix_votes_ring_vote_type', 'votes', ['ring_id', 'vote_type'], unique=False)
    
    # Tokens table
    op.create_table('tokens',
        sa.Column('token_id', sa.String(length=64), nullable=False),
        sa.Column('cred_id_hash', sa.String(length=64), nullable=False),
        sa.Column('reviewer_id', sa.Integer(), nullable=True),
        sa.Column('epoch', sa.Integer(), nullable=False),
        sa.Column('redeemed_bool', sa.Boolean(), nullable=True),
        sa.Column('redeemed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['reviewer_id'], ['reviewers.id'], ),
        sa.PrimaryKeyConstraint('token_id')
    )
    op.create_index(op.f('ix_tokens_token_id'), 'tokens', ['token_id'], unique=False)
    op.create_index(op.f('ix_tokens_cred_id_hash'), 'tokens', ['cred_id_hash'], unique=False)
    op.create_index(op.f('ix_tokens_epoch'), 'tokens', ['epoch'], unique=False)
    op.create_index(op.f('ix_tokens_redeemed_bool'), 'tokens', ['redeemed_bool'], unique=False)
    op.create_index('ix_tokens_cred_epoch', 'tokens', ['cred_id_hash', 'epoch'], unique=False)
    op.create_index('ix_tokens_redeemed_epoch', 'tokens', ['redeemed_bool', 'epoch'], unique=False)
    
    # Escalations table
    op.create_table('escalations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('submission_id', sa.Integer(), nullable=False),
        sa.Column('reason', sa.String(length=100), nullable=False),
        sa.Column('evidence_blob', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('requested_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['submission_id'], ['submissions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_escalations_id'), 'escalations', ['id'], unique=False)
    op.create_index(op.f('ix_escalations_submission_id'), 'escalations', ['submission_id'], unique=False)
    op.create_index(op.f('ix_escalations_status'), 'escalations', ['status'], unique=False)
    
    # Audit logs table
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=True),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_event_type'), 'audit_logs', ['event_type'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)
    op.create_index('ix_audit_logs_event_type_created', 'audit_logs', ['event_type', 'created_at'], unique=False)
    op.create_index('ix_audit_logs_user_created', 'audit_logs', ['user_id', 'created_at'], unique=False)
    
    # Tallies table
    op.create_table('tallies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('submission_id', sa.Integer(), nullable=False),
        sa.Column('count_approve', sa.Integer(), nullable=True),
        sa.Column('count_reject', sa.Integer(), nullable=True),
        sa.Column('count_flag', sa.Integer(), nullable=True),
        sa.Column('count_escalate', sa.Integer(), nullable=True),
        sa.Column('total_votes', sa.Integer(), nullable=True),
        sa.Column('decision', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['submission_id'], ['submissions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tallies_id'), 'tallies', ['id'], unique=False)
    op.create_index(op.f('ix_tallies_submission_id'), 'tallies', ['submission_id'], unique=False)
    
    # Revocations table
    op.create_table('revocations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('credential_hash', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.String(length=100), nullable=False),
        sa.Column('revoked_by', sa.String(length=64), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_revocations_id'), 'revocations', ['id'], unique=False)
    op.create_index(op.f('ix_revocations_credential_hash'), 'revocations', ['credential_hash'], unique=False)
    op.create_index('ix_revocations_cred_hash', 'revocations', ['credential_hash'], unique=False)


def downgrade():
    """Drop all tables"""
    op.drop_table('revocations')
    op.drop_table('tallies')
    op.drop_table('audit_logs')
    op.drop_table('escalations')
    op.drop_table('tokens')
    op.drop_table('votes')
    op.drop_table('reviewers')
    op.drop_table('rings')
    op.drop_table('submissions')
