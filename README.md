# cykingdom

## Usage

```bash
# Setup Rust
rustup target add wasm32-unknown-unknown
cargo install -q worker-build

# Setup dependencies
npm install

# Develop locally
npx wrangler dev
```

## Configuration

This project is automatically deployed via GitHub Actions.

### GitHub Actions Secrets & Variables

- `secrets.CF_API_TOKEN` - Cloudflare API token with `Workers Scripts: Edit`, `D1: Edit`, and `Workers Routes: Edit` permissions.
- `secrets.ADMIN_SECRET` - Password required to register the `admin` account.
- `vars.DOMAIN` - The domain for deployment (e.g., `example.com`).

The D1 database (`cykingdom-db`) will be automatically created and initialized on the first deployment.
