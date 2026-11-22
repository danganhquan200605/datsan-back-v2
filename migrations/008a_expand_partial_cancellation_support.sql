-- Migration 008A: Expand Phase for Partial Cancellation & Idempotency Support
-- Target: Safe schema expansion WITHOUT breaking legacy Backend ON CONFLICT (madatsan)
-- Environment: Supabase Staging & Production
-- Phase: EXPAND (Stage 1 of 2)

DO $$
BEGIN
  -- 1. Add idempotency_key column if not exists
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'idempotency_key'
  ) THEN
    ALTER TABLE public.hoantien ADD COLUMN idempotency_key VARCHAR(128);
  END IF;

  -- 2. Add slot_ids column if not exists
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'slot_ids'
  ) THEN
    ALTER TABLE public.hoantien ADD COLUMN slot_ids INT[];
  END IF;

  -- 3. Backfill legacy records without idempotency_key
  UPDATE public.hoantien 
  SET idempotency_key = 'REFUND_LEGACY_' || mahoantien 
  WHERE idempotency_key IS NULL;

  -- 4. Create unique index on idempotency_key for safe idempotent inserts
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    CREATE UNIQUE INDEX uq_hoantien_idempotency_key ON public.hoantien (idempotency_key);
  END IF;

  -- CRITICAL EXPAND INVARIANT:
  -- hoantien_madatsan_key is INTENTIONALLY PRESERVED during Expand Phase!
  -- This guarantees that the legacy Backend running ON CONFLICT (madatsan) DO NOTHING
  -- will NOT fail with PostgreSQL error 42P10 during deployment.
  
  RAISE NOTICE 'Migration 008A (Expand Phase) completed successfully: columns added, unique index active, UNIQUE(madatsan) preserved.';
END $$;
