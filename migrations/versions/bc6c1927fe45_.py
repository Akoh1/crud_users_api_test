"""empty message

Revision ID: bc6c1927fe45
Revises: 726bcde6a427
Create Date: 2021-12-27 15:07:36.082077

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bc6c1927fe45'
down_revision = '726bcde6a427'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('activated_on', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'activated_on')
    # ### end Alembic commands ###
