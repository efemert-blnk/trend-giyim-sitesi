const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('pg');
const path = require('path');
const session = require('express-session'); // Giriş sistemi için gerekli

const app = express();
const port = process.env.PORT || 3000;

// --- Oturum (Session) Ayarları ---
const sess = {
    secret: process.env.SESSION_SECRET || 'çok-gizli-bir-anahtar-yerelde-kullanmak-icin', // Render'da bunu değiştireceğiz
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 8 // 8 saatlik oturum
    }
};

// Render gibi platformlarda güvenli (HTTPS) bağlantı için
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // proxy'ye güven
    sess.cookie.secure = true; // sadece https üzerinden cookie gönder
}
app.use(session(sess));
// ---

app.use(bodyParser.json());
app.use(cors());

// --- Giriş (Login) API Uç Noktası ---
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || "12345"; // Render'da bunu güvenli bir şifreyle değiştireceğiz

app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === OPERATOR_PASSWORD) {
        req.session.isLoggedIn = true; // Oturumda kullanıcıyı "giriş yaptı" olarak işaretle
        res.status(200).json({ message: 'Giriş başarılı.' });
    } else {
        res.status(401).json({ message: 'Hatalı şifre.' });
    }
});
// ---

// --- Operatör Panelini Koruma Katmanı (Middleware) ---
const authMiddleware = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next(); // Kullanıcı giriş yapmış, istenen sayfaya devam etmesine izin ver
    } else {
        res.redirect('/login.html'); // Giriş yapmamış, giriş sayfasına yönlendir
    }
};
// ---

// --- Statik Dosyaları Sunma ---
// Herkesin erişebileceği dosyalar (anasayfa, giriş sayfası, resimler)
app.use(express.static(path.join(__dirname, 'public'))); 

// operator.html'e erişimi sadece giriş yapmış kullanıcılara aç
app.get('/operator.html', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'operator.html'));
});
// ---

// Veritabanı Bağlantısı ve Kurulumu
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

db.connect(err => {
    if (err) return console.error('Veritabanına bağlanılamadı', err.stack);
    console.log('PostgreSQL veritabanına başarıyla bağlandı.');
    createTables();
});

const createTables = async () => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS hizli_cevaplar (id SERIAL PRIMARY KEY, metin TEXT NOT NULL UNIQUE)`);
        await db.query(`CREATE TABLE IF NOT EXISTS sohbet_gecmisi (id SERIAL PRIMARY KEY, kullanici_id TEXT, gonderen TEXT, mesaj TEXT, tarih TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await db.query(`CREATE TABLE IF NOT EXISTS kullanici_bilgileri (kullanici_id TEXT PRIMARY KEY, isim TEXT)`);
        const res = await db.query("SELECT COUNT(*) as count FROM hizli_cevaplar");
        if (res.rows[0].count == 0) {
            const defaultReplies = ["Merhaba, size nasıl yardımcı olabilirim?", "İlginiz için teşekkür ederiz.", "Konuyu ilgili departmana iletiyorum."];
            for (const reply of defaultReplies) {
                await db.query("INSERT INTO hizli_cevaplar (metin) VALUES ($1)", [reply]);
            }
        }
    } catch (err) { console.error("Tablo oluşturma hatası:", err); }
};

// --- Hızlı Cevaplar API (CRUD) ---
app.get('/api/hizli-cevaplar', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM hizli_cevaplar ORDER BY id');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/hizli-cevaplar', authMiddleware, async (req, res) => {
    try {
        const { metin } = req.body;
        const result = await db.query('INSERT INTO hizli_cevaplar (metin) VALUES ($1) RETURNING id, metin', [metin.trim()]);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(err.code === '23505' ? 409 : 500).json({ error: 'Bu cevap zaten mevcut.' }); }
});

app.put('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const { metin } = req.body;
        const result = await db.query('UPDATE hizli_cevaplar SET metin = $1 WHERE id = $2', [metin.trim(), req.params.id]);
        res.status(200).json({ message: 'Güncellendi.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('DELETE FROM hizli_cevaplar WHERE id = $1', [req.params.id]);
        res.status(200).json({ message: 'Silindi.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- Canlı Destek (Socket.IO) ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// ... (Tüm Socket.IO kodları burada değişiklik olmadan kalıyor) ...
let onlineUsers = new Map();
let conversations = new Map();

io.on('connection', (socket) => {
    // ...
});


// --- Sunucuyu Başlatma ---
const HOST = '0.0.0.0';
server.listen(port, HOST, () => console.log(`${HOST}:${port} adresinde sunucu dinleniyor...`));