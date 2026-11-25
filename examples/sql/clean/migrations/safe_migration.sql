SET lock_timeout = '2s';
ALTER TABLE orders ADD COLUMN status TEXT;

CREATE POLICY tenant_orders ON orders FOR SELECT TO authenticated USING (auth.uid() = owner_id);

SELECT id, total FROM orders ORDER BY id ASC LIMIT 25;

SELECT id FROM orders WHERE deleted_at IS NULL;
