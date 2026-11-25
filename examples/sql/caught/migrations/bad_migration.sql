ALTER TABLE orders ADD COLUMN status TEXT;

CREATE POLICY allow_all_orders ON orders FOR ALL USING (true);

SELECT id, total FROM orders LIMIT 25;

SELECT id FROM orders WHERE deleted_at = NULL;
