-- Rollback Migration 008B: Contract Phase
-- Target: Re-imposes UNIQUE(madatsan) constraint ONLY if zero dependent partial refunds exist
-- Data Safety Guard: Aborts immediately if multiple refund records exist for any booking

DO $$
DECLARE
  v_dup_count INT := 0;
  v_sample_madatsan INT := NULL;
  v_has_partial_data BOOLEAN := FALSE;
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
    RAISE EXCEPTION 'ROLLBACK_ABORTED: Cannot restore UNIQUE(madatsan). Detected % booking(s) (e.g. madatsan=%) with multiple refund records. Re-applying UNIQUE constraint would violate database integrity. Reconcile refund records before rollback.', v_dup_count, v_sample_madatsan;
  END IF;

  -- 2. Check if active partial cancellation records exist
  SELECT EXISTS (
    SELECT 1 FROM public.hoantien 
    WHERE idempotency_key LIKE 'CANCEL_PARTIAL_%' OR slot_ids IS NOT NULL
  ) INTO v_has_partial_data;

  IF v_has_partial_data THEN
    RAISE EXCEPTION 'ROLLBACK_ABORTED: Cannot rollback 008B. Active partial cancellation records exist in hoantien table. Aborting to protect customer refund and audit data.';
  END IF;

  -- 3. If provably clean of partial refunds, safe to restore UNIQUE(madatsan)
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'hoantien_madatsan_key'
  ) THEN
    ALTER TABLE public.hoantien ADD CONSTRAINT hoantien_madatsan_key UNIQUE (madatsan);
    RAISE NOTICE 'Constraint hoantien_madatsan_key restored successfully.';
  END IF;

  -- 4. Drop redundant non-unique index if constraint created its own unique index
  -- Note: PostgreSQL automatically creates hoantien_madatsan_key index with the unique constraint
  RAISE NOTICE 'Rollback Migration 008B completed: database returned to single-refund mode.';
END $$;
