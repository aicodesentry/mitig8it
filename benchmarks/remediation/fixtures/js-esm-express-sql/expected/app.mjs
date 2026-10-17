// An order lookup written as an ES module: express and pg arrive through `import`, which the
// CommonJS loader never sees.
import express from 'express';
import { Pool } from 'pg';

const pool = new Pool();
export const router = express.Router();

router.get('/orders/:id', async (req, res) => {
  const result = await pool.query('SELECT id, total FROM orders WHERE id = $1', [req.params.id]);
  res.json(result.rows);
});
