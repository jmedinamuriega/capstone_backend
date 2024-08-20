"""Add pickup_date and delivery_date to Service model

Revision ID: 92d7f559a820
Revises: 
Create Date: 2024-08-12 02:31:09.512445

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '92d7f559a820'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pickup_date', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('delivery_date', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.drop_column('delivery_date')
        batch_op.drop_column('pickup_date')

    # ### end Alembic commands ###
