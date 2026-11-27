CREATE TABLE billing_orders (
  id BIGINT PRIMARY KEY,
  amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled'))
);

WITH RECURSIVE org_tree(id, depth) AS (
  SELECT id, 0 FROM orgs WHERE parent_id IS NULL
  UNION ALL
  SELECT o.id, t.depth + 1 FROM orgs o JOIN org_tree t ON o.parent_id = t.id WHERE t.depth < 16
)
SELECT id, depth FROM org_tree ORDER BY id LIMIT 1000;
