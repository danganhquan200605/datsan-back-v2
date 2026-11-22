-- Rollback Migration 008: Partial Cancellation Support
-- Data Safety Guard: Refuses rollback if multiple refund records exist for any booking.
-- Preserves idempotency_key and slot_ids if any records depend on them.

DO $$
DECLARE
  v_dup_count INT := 0;
  v_sample_madatsan INT := NULL;
  v_has_idempotency_data BOOLEAN := FALSE;
  v_has_col BOOLEAN := FALSE;
BEGIN
  -- 1. Check if multiple refunds exist for any booking
  SELECT COUNT(*), MIN(madatsan)
  INTO v_dup_count, v_sample_madatsan
  FROM (
    SELECT madatsan 
    FROM public.hoantien 
    WHERE madatsan IS NOT NULL
    GROUP BY madatsan 
    HAVING COUNT(*) > 1
  ) dups;

  IF v_dup_count > 0 THEN
    RAISE EXCEPTION 'ROLLBACK_ABORTED: Cannot rollback Migration 008. Detected % booking(s) (e.g. madatsan=%) with multiple refund records. Re-applying UNIQUE(madatsan) or dropping idempotency/slot columns would cause permanent data loss and constraint violation. Reconcile refund data before rollback.', v_dup_count, v_sample_madatsan;
  END IF;

  -- 2. Check if column exists, and if any records depend on partial cancellation keys
  SELECT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'hoantien' AND column_name = 'idempotency_key'
  ) INTO v_has_col;

  IF v_has_col THEN
    EXECUTE 'SELECT EXISTS (SELECT 1 FROM public.hoantien WHERE idempotency_key LIKE ''CANCEL_PARTIAL_%'' OR slot_ids IS NOT NULL)'
    INTO v_has_idempotency_data;

    IF v_has_idempotency_data THEN
      RAISE EXCEPTION 'ROLLBACK_ABORTED: Cannot drop columns. Active partial cancellation records exist in hoantien table. Aborting rollback to prevent loss of slot and idempotency audit data.';
    END IF;
  END IF;

  -- 3. If completely clean of partial cancellation data, safe to restore UNIQUE(madatsan)
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'hoantien_madatsan_key'
  ) THEN
    ALTER TABLE public.hoantien ADD CONSTRAINT hoantien_madatsan_key UNIQUE (madatsan);
  END IF;

  -- 4. Drop unique index on idempotency_key if exists
  IF EXISTS (
    SELECT 1 FROM pg_indexes 
    WHERE tablename = 'hoantien' AND indexname = 'uq_hoantien_idempotency_key'
  ) THEN
    DROP INDEX IF EXISTS public.uq_hoantien_idempotency_key;
  END IF;

  -- 5. Safe to drop added columns only when zero dependent data exists
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS idempotency_key;
  ALTER TABLE public.hoantien DROP COLUMN IF EXISTS slot_ids;

  RAISE NOTICE 'Rollback Migration 008 completed cleanly: hoantien_madatsan_key restored.';
END $$;
