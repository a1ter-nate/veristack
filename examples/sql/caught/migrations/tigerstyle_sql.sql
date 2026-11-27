CREATE TABLE billing_orders (
  id INT,
  amount_total FLOAT,
  approved_at TIMESTAMP,
  rejected_at TIMESTAMP,
  cancelled_at TIMESTAMP
);

WITH RECURSIVE org_tree AS (
  SELECT id FROM orgs
  UNION ALL
  SELECT o.id FROM orgs o JOIN org_tree t ON o.parent_id = t.id
)
SELECT * FROM org_tree;

DECLARE order_cur CURSOR FOR SELECT id FROM billing_orders;
