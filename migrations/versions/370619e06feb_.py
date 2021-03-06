"""empty message

Revision ID: 370619e06feb
Revises: 
Create Date: 2021-12-24 16:10:31.208276

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '370619e06feb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('public_id', sa.String(length=200), nullable=True),
    sa.Column('first_name', sa.String(length=200), nullable=True),
    sa.Column('last_name', sa.String(length=200), nullable=True),
    sa.Column('email', sa.String(length=200), nullable=True),
    sa.Column('password', sa.String(length=200), nullable=True),
    sa.Column('photo', sa.LargeBinary(), nullable=False),
    sa.Column('standard_user', sa.Boolean(), nullable=False),
    sa.Column('admin_user', sa.Boolean(), nullable=False),
    sa.Column('activated', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('public_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users')
    # ### end Alembic commands ###
