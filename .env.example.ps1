# Environment defaults for local development (scoop Postgres).
# Copy to `.env.ps1` (gitignored) and adjust, or set the vars in your shell.

$env:DB_USERNAME = "postgres"
$env:DB_PASSWORD = "accela_dev"
$env:DB_HOST     = "localhost"
$env:DB_NAME     = "accela_imageboard_dev"

# Dedicated secret for the anonymous-identity HMAC (poster hashes).
# In production: `System.fetch_env!("IP_HASH_SECRET")` — REQUIRED.
# To generate:  :crypto.strong_rand_bytes(32) |> Base.encode16() |> IO.puts()
$env:IP_HASH_SECRET = "dev-only-ip-hash-secret-change-me"
