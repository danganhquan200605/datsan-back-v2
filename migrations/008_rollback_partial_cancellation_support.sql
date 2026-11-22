-- Rollback Migration 008: Partial Cancellation Support
-- Drops unique index uq_hoantien_idempotency_key and columns idempotency_key, slot_ids
-- Re-applies UNIQUE constraint on hoantien(madatsan) IF no duplicates exist

DO $$
BEGIN
  -- 1. Drop unique index on idempotency_key if exists
  IF EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    DROP INDEX IF EXISTS public.uq_hoantien_idempotency_key;
  END IF;

  -- 2. Check if duplicates on madatsan exist before attempting to re-add unique constraint
  IF NOT EXISTS (
    SELECT madatsan FROM public.hoantien GROUP BY madatsan HAVING COUNT(*) > 1
  ) THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conname = 'hoantien_madatsan_key'
    ) THEN
      ALTER TABLE public.hoantien ADD CONSTRAINT hoantien_madatsan_key UNIQUE (madatsan);
    END IF;
  ELSE
    RAISE NOTICE 'Skipping re-creation of unique constraint hoantien_madatsan_key: duplicate refund records exist for some madatsan';
  END IF;

  -- 3. Safely drop added columns
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS idempotency_key;
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS slot_ids;
END $$;
