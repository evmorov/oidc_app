# OpenID Connect Sinatra App

A simple Sinatra application to authenticate users using OpenID Connect (OIDC).

## Install

1. Install Gems:

```bash
bundle install
```

2. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

3. Open `.env` and fill in your IDP details:

```env
IDP_ENDPOINT=https://your-idp.com
IDP_CLIENT_ID=your_client_id
IDP_CLIENT_SECRET=your_client_secret
IDP_REDIRECT_URI=http://localhost:4567/login_callback
```

## Run

Start the app with a specific port:

```bash
PORT=4567 ruby oidc_app.rb
```

## Usage

- Login: http://localhost:4567/login
- Callback: Handled automatically after login
- Refresh Token: http://localhost:4567/refresh
- Logout: http://localhost:4567/logout

## Notes

- Security: SSL verification is disabled for simplicity. Enable it in production.
- Sessions: Uses Sinatra sessions. Configure securely for production.
