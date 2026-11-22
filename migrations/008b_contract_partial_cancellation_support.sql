-- Migration 008B: Contract Phase for Partial Cancellation & Multiple Refunds
-- Target: Drop single-refund restriction ON CONFLICT (madatsan) AFTER Backend V2 is live
-- Prerequisite: Backend V2 (commit 1a4e85a) is fully deployed and verified on Render
-- Environment: Supabase Staging & Production
-- Phase: CONTRACT (Stage 2 of 2)

DO $$
BEGIN
  -- 1. Verify prerequisite: idempotency_key must exist and unique index must be active
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'idempotency_key'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    RAISE EXCEPTION 'PREREQUISITE_FAILED: Migration 008A (Expand Phase) must be applied and verified before running 008B (Contract Phase).';
  END IF;

  -- 2. Drop unique constraint on madatsan if exists
  IF EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'hoantien_madatsan_key'
  ) THEN
    ALTER TABLE public.hoantien DROP CONSTRAINT hoantien_madatsan_key;
    RAISE NOTICE 'Constraint hoantien_madatsan_key successfully dropped.';
  ELSE
    RAISE NOTICE 'Constraint hoantien_madatsan_key already dropped or does not exist.';
  END IF;

  -- 3. Ensure standard index on madatsan exists for query performance
  IF NOT EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'idx_hoantien_madatsan'
  ) THEN
    CREATE INDEX idx_hoantien_madatsan ON public.hoantien (madatsan);
    RAISE NOTICE 'Index idx_hoantien_madatsan created.';
  END IF;

  RAISE NOTICE 'Migration 008B (Contract Phase) completed successfully: multiple partial refunds per booking unlocked.';
END $$;
