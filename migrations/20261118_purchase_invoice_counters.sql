-- Per-workspace sequential purchase invoice numbering.
-- The counter stores the last number issued; the API atomically increments it.
CREATE TABLE IF NOT EXISTS purchase_invoice_counters (
  workspace_id uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  next_number bigint NOT NULL DEFAULT 99 CHECK (next_number >= 99),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO purchase_invoice_counters (workspace_id, next_number)
SELECT p.workspace_id,
       COALESCE(MAX(CASE WHEN p.document_no ~ '^[0-9]+$' THEN p.document_no::bigint END), 99)
FROM purchases p
GROUP BY p.workspace_id
ON CONFLICT (workspace_id) DO UPDATE
SET next_number = GREATEST(purchase_invoice_counters.next_number, EXCLUDED.next_number),
    updated_at = now();
