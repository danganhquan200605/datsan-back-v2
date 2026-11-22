-- Rollback Migration 008A: Expand Phase
-- Reverts changes made by Migration 008A (Expand Phase)
-- Safe only if no active application logic depends on idempotency_key

DO $$
BEGIN
  -- 1. Drop unique index on idempotency_key if exists
  IF EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    DROP INDEX IF EXISTS public.uq_hoantien_idempotency_key;
  END IF;

  -- 2. Drop columns
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS idempotency_key;
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS slot_ids;

  RAISE NOTICE 'Rollback Migration 008A completed: idempotency_key and slot_ids removed.';
END $$;
