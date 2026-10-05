# Shopflx_backend-# SHOPFLIX Backend

SHOPFLIX is an online marketplace backend built with:

- Node.js
- Express
- PostgreSQL
- Paystack
- JWT authentication
- Cloudinary image hosting

## Features

- Customer registration
- Customer login
- JWT authentication
- Customer / Seller / Admin roles
- Product listing
- Seller product uploads
- Seller product management
- Product stock management
- Shopping orders
- Paystack payments
- Payment verification
- Admin user management
- Admin role management
- Admin order status management

## Environment Variables

Create these environment variables on Render:

DATABASE_URL=your_render_postgresql_internal_database_url

PAYSTACK_SECRET_KEY=your_paystack_secret_key

JWT_SECRET=your_long_random_secret

## Local Installation

Install dependencies:

npm install

Start the server:

npm start

## API

Health check:

GET /api/health

Products:

GET /api/products

Product:

GET /api/products/:id

Register:

POST /api/auth/register

Login:

POST /api/auth/login

Current user:

GET /api/auth/me

Create product:

POST /api/products

Seller products:

GET /api/seller/products

Create order:

POST /api/orders

Initialize Paystack:

POST /api/payments/initialize

Verify Paystack:

GET /api/payments/verify/:reference

Order:

GET /api/orders/:id

Admin users:

GET /api/admin/users

Admin role update:

PATCH /api/admin/users/:id/role

Admin order status:

PATCH /api/orders/:id/status

## Render

Build Command:

npm install

Start Command:

npm start

Required environment variables:

DATABASE_URL
PAYSTACK_SECRET_KEY
JWT_SECRET

After deployment, test:

/api/health

A successful response should contain:

{
  "status": "ok",
  "database": "connected",
  "paystack": "configured",
  "jwt": "configured"
}

## Security

Never put PAYSTACK_SECRET_KEY inside the frontend.

Never commit secret keys to GitHub.

JWT_SECRET must remain private.
