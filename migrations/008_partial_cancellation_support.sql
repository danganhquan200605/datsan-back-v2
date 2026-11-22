-- Migration 008: Partial Cancellation Support & Hoantien Constraint Hardening
-- Allows multiple refund records per booking for partial cancellation workflows
-- Drops UNIQUE constraint on hoantien(madatsan) if exists and creates standard index
-- Adds idempotency_key and slot_ids columns with unique index on idempotency_key

DO $$
BEGIN
  -- 1. Drop unique constraint on madatsan if exists
  IF EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'hoantien_madatsan_key'
  ) THEN
    ALTER TABLE public.hoantien DROP CONSTRAINT hoantien_madatsan_key;
  END IF;

  -- 2. Add idempotency_key column if not exists
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'idempotency_key'
  ) THEN
    ALTER TABLE public.hoantien ADD COLUMN idempotency_key VARCHAR(128);
  END IF;

  -- 3. Add slot_ids column if not exists
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'slot_ids'
  ) THEN
    ALTER TABLE public.hoantien ADD COLUMN slot_ids INT[];
  END IF;

  -- 4. Backfill legacy records without idempotency_key
  UPDATE public.hoantien 
  SET idempotency_key = 'REFUND_LEGACY_' || mahoantien 
  WHERE idempotency_key IS NULL;

  -- 5. Create unique index on idempotency_key
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    CREATE UNIQUE INDEX uq_hoantien_idempotency_key ON public.hoantien (idempotency_key);
  END IF;

  -- 6. Ensure index on madatsan exists for fast query performance
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'idx_hoantien_madatsan'
  ) THEN
    CREATE INDEX idx_hoantien_madatsan ON public.hoantien (madatsan);
  END IF;
END $$;
