# DatSan Back v2

Express API for the DatSan frontend. This service proxies the limited set of Supabase tables and the `san-images` storage bucket used by the inherited UI.

## Run locally

1. Install Node.js 20.19+ or 22.12+.
2. Copy `.env.example` to `.env`; set the Supabase project URL and anon key.
3. Set `ALLOWED_ORIGINS` to the frontend origin(s), comma separated.
4. Run `npm install` and `npm start`.

## Security rollout

The API uses the Supabase **anon** key and forwards verified Supabase access tokens for protected operations. It never uses a service-role key. Public field availability is exposed through a limited RPC; booking creation goes through a transaction that validates the selected slots and computes the price on the database side.

Before deploying these code changes, review and apply `supabase/migrations/20261117_auth_rls_bookings.sql` to the Supabase project. The migration replaces the current permissive `public` policies and adds a `nguoidung.auth_user_id` link. The project is also used by the legacy app, so applying it changes what that app can read and write; its demo sign-in and direct booking writes will no longer work. Phone Auth is currently disabled in Supabase and needs a configured SMS provider before OTP login can work. Do not expose a Supabase service-role key.

The API adapter refreshes screen data by polling; it does not implement Supabase Realtime.
