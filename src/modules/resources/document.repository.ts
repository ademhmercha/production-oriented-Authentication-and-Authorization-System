import { Database } from '../../infrastructure/database/pool';

export interface DocumentRow {
  id: string;
  owner_id: string;
  title: string;
  content: string;
  created_at: Date;
  updated_at: Date;
}

export interface CreateDocumentInput {
  ownerId: string;
  title: string;
  content?: string;
}

export class DocumentRepository {
  constructor(private readonly db: Database) {}

  async create(input: CreateDocumentInput): Promise<DocumentRow> {
    const result = await this.db.query<DocumentRow>(
      `INSERT INTO documents (owner_id, title, content)
       VALUES ($1, $2, $3)
       RETURNING id, owner_id, title, content, created_at, updated_at`,
      [input.ownerId, input.title, input.content ?? ''],
    );
    return result.rows[0];
  }

  async listByOwner(ownerId: string, limit = 50, offset = 0): Promise<DocumentRow[]> {
    const result = await this.db.query<DocumentRow>(
      `SELECT id, owner_id, title, content, created_at, updated_at
       FROM documents WHERE owner_id = $1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [ownerId, limit, offset],
    );
    return result.rows;
  }

  async listAll(limit = 50, offset = 0): Promise<DocumentRow[]> {
    const result = await this.db.query<DocumentRow>(
      `SELECT id, owner_id, title, content, created_at, updated_at
       FROM documents ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    return result.rows;
  }

  async findById(id: string): Promise<DocumentRow | null> {
    const result = await this.db.query<DocumentRow>(
      `SELECT id, owner_id, title, content, created_at, updated_at
       FROM documents WHERE id = $1`,
      [id],
    );
    return result.rows[0] ?? null;
  }

  async remove(id: string): Promise<boolean> {
    const result = await this.db.query('DELETE FROM documents WHERE id = $1', [id]);
    return (result.rowCount ?? 0) > 0;
  }
}
