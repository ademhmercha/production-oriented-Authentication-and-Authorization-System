import { Router } from 'express';
import { z } from 'zod';
import { AppError } from '../../common/errors';
import type { Request } from 'express';
import { validate } from '../../common/validation/validate';
import { DocumentRepository } from './document.repository';
import { ResourceIdentity, requireIdentity, requireResourceScope } from './resource.middlewares';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const createSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().max(50_000).optional(),
});

function identity(req: Request): ResourceIdentity {
  return req.identity as ResourceIdentity;
}

export function createDocumentsRoutes(documents: DocumentRepository): Router {
  const router = Router();

  router.use(requireIdentity());

  /** Echoes the verified identity - handy for debugging and e2e tests. */
  router.get('/me', (req, res) => {
    res.json(identity(req));
  });

  router.get(
    '/documents',
    requireResourceScope('api.read'),
    async (req, res, next) => {
      try {
        const me = identity(req);
        const rows = me.userId
          ? await documents.listByOwner(me.userId)
          : await documents.listAll(); // service clients see all (audit-style read)
        res.json({
          data: rows.map((r) => ({
            id: r.id,
            owner_id: r.owner_id,
            title: r.title,
            content: r.content,
            created_at: r.created_at,
            updated_at: r.updated_at,
          })),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  router.post(
    '/documents',
    requireResourceScope('api.write'),
    validate({ body: createSchema }),
    async (req, res, next) => {
      try {
        const me = identity(req);
        if (!me.userId) {
          throw new AppError(403, 'SERVICE_FORBIDDEN', 'Service clients cannot create documents');
        }
        const row = await documents.create({
          ownerId: me.userId,
          title: req.body.title as string,
          content: req.body.content as string | undefined,
        });
        res.status(201).json({ id: row.id, title: row.title, created_at: row.created_at });
      } catch (err) {
        next(err);
      }
    },
  );

  router.delete(
    '/documents/:id',
    requireResourceScope('api.write'),
    async (req, res, next) => {
      try {
        const me = identity(req);
        const id = String(req.params.id);
        if (!UUID_RE.test(id)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid document id');

        const row = await documents.findById(id);
        if (!row || (me.userId && row.owner_id !== me.userId)) {
          // 404 for foreign resources - do not leak existence.
          throw new AppError(404, 'NOT_FOUND', 'Document not found');
        }
        const isAdmin = me.roles.includes('admin');
        if (me.userId && !isAdmin) {
          throw new AppError(403, 'FORBIDDEN', 'Only the owner or an admin can delete');
        }
        await documents.remove(id);
        res.status(204).send();
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
