"""Письмо как сущность: Letter/LetterFile, связь индикатор-письмо, решения аналитика

Раньше каждый загруженный файл был отдельным «письмом» (таблица documents),
а номер письма дублировался в каждой строке. Теперь письмо — это номер и дата
(letters), у него несколько файлов (letter_files), а индикаторы связаны с
письмами связью многие-ко-многим: один домен приходит в нескольких письмах.

Данные переносятся: документы с одинаковым номером склеиваются в одно письмо,
файлы становятся его вложениями, а привязки индикаторов — строками в таблицах
связи. Ничего не теряется.

Revision ID: e3f86b6be9f3
Revises: b4e07c2a91d3
Create Date: 2026-08-13 11:35:31.091212

"""
import re

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e3f86b6be9f3'
down_revision = 'b4e07c2a91d3'
branch_labels = None
depends_on = None


def _number_key(value: str) -> str:
    """Тот же ключ склейки, что и в app/services/fstec/letters.py."""
    if not value:
        return ""
    cleaned = re.sub(r"[^\d/а-яё-]", "", str(value).lower().replace("№", ""))
    cleaned = re.sub(r"/+", "/", cleaned).strip("/-")
    return cleaned


def _migrate_documents() -> None:
    """Разложить старые documents по письмам и файлам, сохранив привязки."""
    bind = op.get_bind()
    documents = bind.execute(sa.text(
        "SELECT id, filename, uploaded_at, uploaded_by, entries_found, notes,"
        " letter_number, letter_date, stored_name, content_type, file_size,"
        " pdf_stored_name, pdf_original_name, pdf_size"
        " FROM documents ORDER BY id"
    )).mappings().all()
    if not documents:
        return

    # Документы с одним номером — это одно письмо. Документы без номера
    # остаются каждый сам по себе: склеивать их не по чему.
    letter_by_key: dict[str, int] = {}
    letter_by_document: dict[int, int] = {}
    file_by_document: dict[int, int] = {}

    for doc in documents:
        key = _number_key(doc["letter_number"] or "")
        letter_id = letter_by_key.get(key) if key else None

        if letter_id is None:
            letter_id = bind.execute(
                sa.text(
                    "INSERT INTO letters"
                    " (number, number_key, letter_date, subject, notes,"
                    "  created_at, created_by)"
                    " VALUES (:number, :key, :date, '', :notes, :created, :by)"
                ),
                {
                    "number": doc["letter_number"] or "",
                    "key": key,
                    "date": doc["letter_date"],
                    "notes": doc["notes"] or "",
                    "created": doc["uploaded_at"],
                    "by": doc["uploaded_by"],
                },
            ).lastrowid
            if key:
                letter_by_key[key] = letter_id

        letter_by_document[doc["id"]] = letter_id

        file_id = bind.execute(
            sa.text(
                "INSERT INTO letter_files"
                " (letter_id, filename, stored_name, content_type, file_size,"
                "  sha256, is_primary, entries_found, parse_error,"
                "  uploaded_at, uploaded_by)"
                " VALUES (:letter, :name, :stored, :ctype, :size,"
                "         '', 1, :found, '', :uploaded, :by)"
            ),
            {
                "letter": letter_id,
                "name": doc["filename"],
                "stored": doc["stored_name"] or "",
                "ctype": doc["content_type"] or "",
                "size": doc["file_size"] or 0,
                "found": doc["entries_found"] or 0,
                "uploaded": doc["uploaded_at"],
                "by": doc["uploaded_by"],
            },
        ).lastrowid
        file_by_document[doc["id"]] = file_id

        # Отдельно приложенный PDF был полем документа — теперь это обычный
        # второй файл письма.
        if doc["pdf_stored_name"]:
            bind.execute(
                sa.text(
                    "INSERT INTO letter_files"
                    " (letter_id, filename, stored_name, content_type,"
                    "  file_size, sha256, is_primary, entries_found,"
                    "  parse_error, uploaded_at, uploaded_by)"
                    " VALUES (:letter, :name, :stored, 'application/pdf',"
                    "         :size, '', 0, 0, '', :uploaded, :by)"
                ),
                {
                    "letter": letter_id,
                    "name": doc["pdf_original_name"] or "письмо.pdf",
                    "stored": doc["pdf_stored_name"],
                    "size": doc["pdf_size"] or 0,
                    "uploaded": doc["uploaded_at"],
                    "by": doc["uploaded_by"],
                },
            )

    # Привязки индикаторов к документам становятся связями с письмами.
    for table, link in (("block_entries", "block_entry_letters"),
                        ("url_entries", "url_entry_letters"),
                        ("ioc_hashes", "ioc_hash_letters")):
        rows = bind.execute(sa.text(
            f"SELECT id, document_id FROM {table} WHERE document_id IS NOT NULL"
        )).mappings().all()
        seen = set()
        for row in rows:
            letter_id = letter_by_document.get(row["document_id"])
            if letter_id is None or (row["id"], letter_id) in seen:
                continue
            seen.add((row["id"], letter_id))
            bind.execute(
                sa.text(
                    f"INSERT INTO {link} (entry_id, letter_id, file_id)"
                    " VALUES (:entry, :letter, :file)"
                ),
                {
                    "entry": row["id"],
                    "letter": letter_id,
                    "file": file_by_document.get(row["document_id"]),
                },
            )


def upgrade():
    op.create_table(
        'letters',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('number', sa.String(length=120), nullable=False,
                  server_default=''),
        sa.Column('number_key', sa.String(length=120), nullable=False,
                  server_default=''),
        sa.Column('letter_date', sa.Date(), nullable=True),
        sa.Column('subject', sa.String(length=500), nullable=False,
                  server_default=''),
        sa.Column('notes', sa.String(length=1000), nullable=False,
                  server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('letters', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_letters_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_letters_letter_date'), ['letter_date'], unique=False)
        batch_op.create_index(batch_op.f('ix_letters_number'), ['number'], unique=False)
        batch_op.create_index(batch_op.f('ix_letters_number_key'), ['number_key'], unique=False)

    op.create_table(
        'letter_files',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('letter_id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('stored_name', sa.String(length=255), nullable=False,
                  server_default=''),
        sa.Column('content_type', sa.String(length=100), nullable=False,
                  server_default=''),
        sa.Column('file_size', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sha256', sa.String(length=64), nullable=False,
                  server_default=''),
        sa.Column('is_primary', sa.Boolean(), nullable=False,
                  server_default=sa.text('0')),
        sa.Column('entries_found', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('parse_error', sa.String(length=500), nullable=False,
                  server_default=''),
        sa.Column('uploaded_at', sa.DateTime(), nullable=True),
        sa.Column('uploaded_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['letter_id'], ['letters.id'], ),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('letter_files', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_letter_files_letter_id'), ['letter_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_letter_files_sha256'), ['sha256'], unique=False)

    for name, entry_table in (('block_entry_letters', 'block_entries'),
                              ('url_entry_letters', 'url_entries'),
                              ('ioc_hash_letters', 'ioc_hashes')):
        op.create_table(
            name,
            sa.Column('entry_id', sa.Integer(), nullable=False),
            sa.Column('letter_id', sa.Integer(), nullable=False),
            sa.Column('file_id', sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(['entry_id'], [f'{entry_table}.id'],
                                    ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['file_id'], ['letter_files.id'],
                                    ondelete='SET NULL'),
            sa.ForeignKeyConstraint(['letter_id'], ['letters.id'],
                                    ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('entry_id', 'letter_id')
        )

    # Переносим данные, пока старые таблица и колонки ещё на месте.
    _migrate_documents()

    with op.batch_alter_table('block_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('decision_note', sa.String(length=500),
                                      nullable=False, server_default=''))
        batch_op.add_column(sa.Column('decided_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('decided_by', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_block_entries_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_block_entries_status'), ['status'], unique=False)
        batch_op.create_foreign_key('fk_block_entries_decided_by', 'users',
                                    ['decided_by'], ['id'])
        batch_op.drop_column('document_id')

    with op.batch_alter_table('ioc_hashes', schema=None) as batch_op:
        batch_op.alter_column('value',
                              existing_type=sa.VARCHAR(length=64),
                              type_=sa.String(length=128),
                              existing_nullable=False)
        batch_op.create_index(batch_op.f('ix_ioc_hashes_created_at'), ['created_at'], unique=False)
        batch_op.drop_column('document_id')

    with op.batch_alter_table('url_entries', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_url_entries_created_at'), ['created_at'], unique=False)
        batch_op.drop_column('document_id')

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_documents_uploaded_at'))
    op.drop_table('documents')


def downgrade():
    """Возврат к прежней схеме. Письма схлопываются обратно в документы:
    у индикатора остаётся только первое письмо-источник."""
    op.create_table(
        'documents',
        sa.Column('id', sa.INTEGER(), nullable=False),
        sa.Column('filename', sa.VARCHAR(length=255), nullable=False),
        sa.Column('uploaded_at', sa.DATETIME(), nullable=True),
        sa.Column('uploaded_by', sa.INTEGER(), nullable=True),
        sa.Column('entries_found', sa.INTEGER(), nullable=False,
                  server_default='0'),
        sa.Column('notes', sa.VARCHAR(length=500), nullable=True),
        sa.Column('letter_number', sa.VARCHAR(length=120), nullable=True),
        sa.Column('letter_date', sa.DATE(), nullable=True),
        sa.Column('stored_name', sa.VARCHAR(length=255), nullable=True),
        sa.Column('content_type', sa.VARCHAR(length=100), nullable=True),
        sa.Column('file_size', sa.INTEGER(), nullable=True),
        sa.Column('pdf_stored_name', sa.VARCHAR(length=255), nullable=True),
        sa.Column('pdf_original_name', sa.VARCHAR(length=255), nullable=True),
        sa.Column('pdf_size', sa.INTEGER(), nullable=True),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_documents_uploaded_at'), ['uploaded_at'], unique=False)

    bind = op.get_bind()
    bind.execute(sa.text(
        "INSERT INTO documents (id, filename, uploaded_at, uploaded_by,"
        " entries_found, notes, letter_number, letter_date, stored_name,"
        " content_type, file_size)"
        " SELECT f.id, f.filename, f.uploaded_at, f.uploaded_by,"
        " f.entries_found, l.notes, l.number, l.letter_date, f.stored_name,"
        " f.content_type, f.file_size"
        " FROM letter_files f JOIN letters l ON l.id = f.letter_id"
    ))

    with op.batch_alter_table('url_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('document_id', sa.INTEGER(), nullable=True))
        batch_op.drop_index(batch_op.f('ix_url_entries_created_at'))

    with op.batch_alter_table('ioc_hashes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('document_id', sa.INTEGER(), nullable=True))
        batch_op.drop_index(batch_op.f('ix_ioc_hashes_created_at'))
        batch_op.alter_column('value',
                              existing_type=sa.String(length=128),
                              type_=sa.VARCHAR(length=64),
                              existing_nullable=False)

    with op.batch_alter_table('block_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('document_id', sa.INTEGER(), nullable=True))
        batch_op.drop_constraint('fk_block_entries_decided_by', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_block_entries_status'))
        batch_op.drop_index(batch_op.f('ix_block_entries_created_at'))
        batch_op.drop_column('decided_by')
        batch_op.drop_column('decided_at')
        batch_op.drop_column('decision_note')

    for table, link in (("block_entries", "block_entry_letters"),
                        ("url_entries", "url_entry_letters"),
                        ("ioc_hashes", "ioc_hash_letters")):
        bind.execute(sa.text(
            f"UPDATE {table} SET document_id = ("
            f" SELECT MIN(COALESCE(k.file_id, 0)) FROM {link} k"
            f" WHERE k.entry_id = {table}.id AND k.file_id IS NOT NULL)"
        ))

    op.drop_table('url_entry_letters')
    op.drop_table('ioc_hash_letters')
    op.drop_table('block_entry_letters')
    with op.batch_alter_table('letter_files', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_letter_files_sha256'))
        batch_op.drop_index(batch_op.f('ix_letter_files_letter_id'))
    op.drop_table('letter_files')
    with op.batch_alter_table('letters', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_letters_number_key'))
        batch_op.drop_index(batch_op.f('ix_letters_number'))
        batch_op.drop_index(batch_op.f('ix_letters_letter_date'))
        batch_op.drop_index(batch_op.f('ix_letters_created_at'))
    op.drop_table('letters')
