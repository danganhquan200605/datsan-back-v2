# DatSan Back v2

Express API for the DatSan frontend. This service proxies the limited set of Supabase tables and the `san-images` storage bucket used by the inherited UI.

## Run locally

1. Install Node.js 20.19+ or 22.12+.
2. Copy `.env.example` to `.env`; set the Supabase project URL and anon key.
3. Set `ALLOWED_ORIGINS` to the frontend origin(s), comma separated.
4. Run `npm install` and `npm start`.

## Important

The browser no longer contains Supabase configuration and calls this API instead. The API currently uses the Supabase **anon** key, so database Row Level Security policies remain the actual access control. The inherited app stores a user profile in `sessionStorage` and has a demo OTP flow; it does not yet provide trustworthy server-side authentication or role authorization. Do not expose a Supabase service-role key here. Configure restrictive RLS before public use, and replace demo login and booking writes with authenticated, validated API operations. The API adapter currently does not implement Supabase realtime; screens refresh on their existing fetch triggers.
