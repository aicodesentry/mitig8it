// An account lookup in TypeScript, written as an ES module. The relative import names `limits`
// without a suffix, which Node's ES module resolver never completes on its own.
import { Pool } from 'pg';
import { MAX_ROWS } from './limits';

interface Account { id: number; email: string }

const pool = new Pool();

export async function findAccounts(email: string): Promise<Account[]> {
  const result = await pool.query(`SELECT id, email FROM accounts WHERE email = '${email}'`);
  return result.rows.slice(0, MAX_ROWS);
}
