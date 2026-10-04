require("dotenv").config();
const express = require("express");
const cors = require('cors');
const path = require("path");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-to-a-long-random-secret";

// MULTER SETUP (Image Uploads ke liye Folder create karna)
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "",
  key_secret: process.env.RAZORPAY_KEY_SECRET || ""
});

// Database Setup
const db = new Database(path.join(__dirname, "store.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE,
  razorpay_order_id TEXT UNIQUE,
  razorpay_payment_id TEXT,
  razorpay_signature TEXT,
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity >= 10),
  total INTEGER NOT NULL,
  customer_name TEXT,
  customer_email TEXT,
  customer_phone TEXT,
  customer_address TEXT,
  payment_status TEXT NOT NULL DEFAULT 'created',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  sellingPrice INTEGER NOT NULL,
  costPerPurchase INTEGER NOT NULL,
  meeshoCost INTEGER DEFAULT 0,
  dropdashCost INTEGER DEFAULT 0,
  image_url TEXT
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('announcement', '🎉 Welcome to ShopEase! Minimum Order Quantity is 10 items.');
`);

// Admin Account Auto-Create Setup
const adminEmail = (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "lak@123";
const existingAdmin = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existingAdmin) { 
  const hash = bcrypt.hashSync(adminPassword, 10); 
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)").run("Administrator", adminEmail, hash, "admin"); 
}

app.use(cors({
    origin: 'https://shopease-public.vercel.app', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Security Middlewares
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "Login required" });
  try { 
      req.user = jwt.verify(token, JWT_SECRET); 
      next(); 
  }
  catch { return res.status(401).json({ message: "Invalid or expired session" }); }
}

function adminOnly(req, res, next) { 
  if(req.user.role !== "admin") return res.status(403).json({ success: false, message: "Admin access required" }); 
  next(); 
}

// ==========================================
// AUTHENTICATION
// ==========================================
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password || password.length < 6) return res.status(400).json({ message: "Email and password (min 6 chars) required" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name || "User", email.trim().toLowerCase(), hash);
    const user = { id: r.lastInsertRowid, name: name || "User", email: email.trim().toLowerCase(), role: "customer" };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user });
  } catch (e) { res.status(409).json({ message: "Email already registered" }); }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=?").get((email || "").trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password || "", user.password_hash))) return res.status(401).json({ message: "Invalid email or password" });
  const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
  const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token, user: safeUser });
});

// ==========================================
// PUBLIC & CUSTOMER APIs
// ==========================================
app.get("/api/products", (req, res) => {
  res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all());
});

app.get("/api/announcement", (req, res) => {
  const setting = db.prepare("SELECT value FROM settings WHERE key='announcement'").get();
  res.json({ announcement: setting ? setting.value : "" });
});

app.post("/api/create-payment-order", auth, async (req, res) => {
  try {
    const { productId, quantity, customer } = req.body;
    const product = db.prepare("SELECT * FROM products WHERE id=?").get(Number(productId));
    if (!product) return res.status(400).json({ message: "Invalid product" });
    
    const total = product.sellingPrice * Number(quantity) * 100; 
    const razorpayOrder = await razorpay.orders.create({ amount: total, currency: "INR", receipt: `rcpt_${Date.now()}` });
    const orderNumber = `ORD-${String(db.prepare("SELECT COALESCE(MAX(id),0)+1 AS next FROM orders").get().next).padStart(6, "0")}`;

    const result = db.prepare(`INSERT INTO orders (order_number, razorpay_order_id, user_id, product_id, product_name, quantity, total, customer_name, customer_email, customer_phone, customer_address, payment_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created')`).run(orderNumber, razorpayOrder.id, req.user.id, product.id, product.name, Number(quantity), total, customer?.name||"", customer?.email||"", customer?.phone||"", customer?.address||"");
    
    res.json({ keyId: process.env.RAZORPAY_KEY_ID, orderId: result.lastInsertRowid, razorpayOrderId: razorpayOrder.id, amount: total, currency: "INR" });
  } catch (error) { res.status(500).json({ message: "Unable to create payment order" }); }
});

app.post("/api/verify-payment", auth, (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, orderId } = req.body;
    const expectedSignature = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");
    
    if (!razorpay_signature || expectedSignature.length !== razorpay_signature.length || !crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(razorpay_signature))) {
      db.prepare("UPDATE orders SET payment_status='verification_failed' WHERE id=?").run(orderId);
      return res.status(400).json({ success: false, message: "Invalid payment signature" });
    }
    
    db.prepare(`UPDATE orders SET razorpay_payment_id=?, razorpay_signature=?, payment_status='paid', paid_at=CURRENT_TIMESTAMP WHERE id=?`).run(razorpay_payment_id, razorpay_signature, orderId);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ success: false, message: "Payment verification error" }); }
});

app.get("/api/orders", auth, (req, res) => {
  res.json(db.prepare("SELECT * FROM orders WHERE user_id=? AND payment_status='paid' ORDER BY id DESC").all(req.user.id));
});

// ==========================================
// ADMIN DASHBOARD APIs
// ==========================================
app.get("/api/admin/dashboard", auth, adminOnly, (req, res) => {
  const stats = {
    revenue: db.prepare("SELECT SUM(total) as sum FROM orders WHERE payment_status='paid'").get().sum || 0,
    totalOrders: db.prepare("SELECT COUNT(*) as count FROM orders WHERE payment_status='paid'").get().count || 0,
    totalCustomers: db.prepare("SELECT COUNT(*) as count FROM users WHERE role='customer'").get().count || 0
  };
  
  const orders = db.prepare("SELECT o.*, u.name user_name, u.email user_email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100").all();
  res.json({ stats, orders });
});

// Announcement Update
app.post("/api/admin/announcement", auth, adminOnly, (req, res) => {
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('announcement', ?)").run(req.body.announcement || "");
  res.json({ success: true });
});

// Product Upload
app.post("/api/admin/products", auth, adminOnly, upload.single('productImage'), (req, res) => {
  const { name, sellingPrice, costPerPurchase } = req.body;
  const image_url = req.file ? `/uploads/${req.file.filename}` : '';
  
  if (!name || !sellingPrice || !costPerPurchase || !image_url) {
    return res.status(400).json({ success: false, message: "All product fields and image are required" });
  }

  try {
    const stmt = db.prepare('INSERT INTO products (name, sellingPrice, costPerPurchase, image_url) VALUES (?, ?, ?, ?)');
    stmt.run(name, Number(sellingPrice), Number(costPerPurchase), image_url);
    res.json({ success: true, message: "Product uploaded successfully!" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error adding product" });
  }
});

// Product Modification (Edit)
app.put('/api/admin/products/:id', auth, adminOnly, (req, res) => {
  try {
    const { name, sellingPrice, costPerPurchase } = req.body;
    const stmt = db.prepare('UPDATE products SET name = ?, sellingPrice = ?, costPerPurchase = ? WHERE id = ?');
    stmt.run(name, Number(sellingPrice), Number(costPerPurchase), req.params.id);
    res.json({ success: true, message: "Product modified successfully!" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error updating product" });
  }
});

// Product Delete
app.delete('/api/admin/products/:id', auth, adminOnly, (req, res) => {
  try {
    db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
    res.json({ success: true, message: "Product deleted successfully!" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error deleting product" });
  }
});

app.listen(PORT, () => console.log(`ShopEase running at http://localhost:${PORT}`));