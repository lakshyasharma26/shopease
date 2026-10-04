# ShopEase Razorpay + Authentication

## Features
- Real Razorpay Checkout integration
- Secure Razorpay signature verification
- Register/Login with bcrypt password hashing
- JWT authentication
- Each user can only view their own paid orders
- SQLite database
- MOQ enforced at 10 on server
- Serial order numbers

## Setup
1. Copy `.env.example` to `.env`.
2. Add Razorpay Test Mode keys and a long JWT_SECRET.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

Important: Never expose RAZORPAY_KEY_SECRET or JWT_SECRET in frontend code.

## Admin Dashboard
Set ADMIN_EMAIL and ADMIN_PASSWORD in `.env` before first start. Login with that account to see the Admin button and dashboard with paid orders, customers and revenue.
