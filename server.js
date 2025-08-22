const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('pg');
const path = require('path');
const session = require('express-session');
const sharedsession = require('socket.io-express-session');
const pgSimple = require('connect-pg-simple');

const app = express();
const port = process.env.PORT || 3000;

// Veritabanı Bağlantısı (Session Store için de kullanılacak)
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

db.connect(err => {
    if (err) return console.error('Veritabanına bağlanılamadı', err.stack);
    console.log('PostgreSQL veritabanına başarıyla bağlandı.');
    createTables();
});

// Oturum (Session) Ayarları
const sessionMiddleware = session({
    store: new (pgSimple(session))({
        pool: db, // Mevcut veritabanı bağlantısını kullan
        tableName: 'user_sessions' // Oturumları saklamak için tablo adı
    }),
    secret: process.env.SESSION_SECRET || 'cok-gizli-bir-anahtar-yerelde-kullanmak-icin',
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 günlük oturum
        secure: process.env.NODE_ENV === 'production' // Sadece HTTPS'te cookie gönder
    }
});

app.use(sessionMiddleware);
// ---

app.use(bodyParser.json());
app.use(cors());

// Giriş (Login) API
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || "12345";

app.post('/login', (req, res) => {
    if (req.body.password === OPERATOR_PASSWORD) {
        req.session.isLoggedIn = true;
        res.status(200).json({ message: 'Giriş başarılı.' });
    } else {
        res.status(401).json({ message: 'Hatalı şifre.' });
    }
});

// Operatör Panelini Koruma
const authMiddleware = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/login.html');
    }
};

// Statik Dosyaları Sunma
app.use(express.static(path.join(__dirname, 'public')));
app.get('/operator.html', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'operator.html'));
});

const createTables = async () => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS hizli_cevaplar (id SERIAL PRIMARY KEY, metin TEXT NOT NULL UNIQUE)`);
        await db.query(`CREATE TABLE IF NOT EXISTS sohbet_gecmisi (id SERIAL PRIMARY KEY, kullanici_id TEXT, gonderen TEXT, mesaj TEXT, tarih TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await db.query(`CREATE TABLE IF NOT EXISTS kullanici_bilgileri (kullanici_id TEXT PRIMARY KEY, isim TEXT)`);

        const res = await db.query("SELECT COUNT(*) as count FROM hizli_cevaplar");
        if (res.rows[0].count == 0) {
            const defaultReplies = [
                "Merhaba, size nasıl yardımcı olabilirim?", "İlginiz için teşekkür ederiz.", "Konuyu ilgili departmana iletiyorum, lütfen bekleyiniz.", "Farklı bir konuda yardımcı olabilir miyim?", "Ürünlerimiz hakkında detaylı bilgiye web sitemizden ulaşabilirsiniz.", "Stoklarımız güncellenmektedir, takipte kalınız."
            ];
            for (const reply of defaultReplies) {
                await db.query("INSERT INTO hizli_cevaplar (metin) VALUES ($1)", [reply]);
            }
            console.log("Varsayılan hızlı cevaplar eklendi.");
        }
    } catch (err) {
        console.error("Tablo oluşturma hatası:", err);
    }
};

// Hızlı Cevaplar API (CRUD)
app.get('/api/hizli-cevaplar', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM hizli_cevaplar ORDER BY id');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/hizli-cevaplar', authMiddleware, async (req, res) => {
    try {
        const { metin } = req.body;
        if (!metin) return res.status(400).json({ error: 'Metin boş olamaz.' });
        const result = await db.query('INSERT INTO hizli_cevaplar (metin) VALUES ($1) RETURNING id, metin', [metin.trim()]);
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(err.code === '23505' ? 409 : 500).json({ error: 'Bu cevap zaten mevcut.' }); }
});

app.put('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const { metin } = req.body;
        if (!metin) return res.status(400).json({ error: 'Metin boş olamaz.' });
        const result = await db.query('UPDATE hizli_cevaplar SET metin = $1 WHERE id = $2', [metin.trim(), req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Cevap bulunamadı.' });
        res.status(200).json({ message: 'Güncellendi.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('DELETE FROM hizli_cevaplar WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Cevap bulunamadı.' });
        res.status(200).json({ message: 'Silindi.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Canlı Destek (Socket.IO)
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.use(sharedsession(sessionMiddleware, { autoSave: true }));

let onlineUsers = new Map();
let conversations = new Map();

io.on('connection', (socket) => {
    console.log('Yeni bir bağlantı:', socket.id);

    socket.on('register as operator', () => {
        if (socket.handshake.session.isLoggedIn) {
            console.log(`Doğrulanmış operatör bağlandı: ${socket.id}`);
            socket.join('operators');
            socket.emit('all conversations', Array.from(conversations.values()));
        } else {
            console.log(`Yetkisiz operatör bağlantısı reddedildi: ${socket.id}`);
        }
    });

    socket.on('user session connect', async ({ userId }) => {
        onlineUsers.set(socket.id, userId);
        let convo = conversations.get(userId);
        
        if (!convo) {
            const userInfoRes = await db.query("SELECT isim FROM kullanici_bilgileri WHERE kullanici_id = $1", [userId]);
            const historyRes = await db.query("SELECT gonderen, mesaj FROM sohbet_gecmisi WHERE kullanici_id = $1 ORDER BY tarih ASC", [userId]);
            
            convo = {
                id: userId,
                name: userInfoRes.rows[0]?.isim || `Kullanıcı #${userId.substring(0, 4)}`,
                messages: historyRes.rows.map(r => ({ from: r.gonderen, text: r.mesaj })),
                lastMessage: historyRes.rows.length > 0 ? historyRes.rows[historyRes.rows.length - 1].mesaj : "Yeni sohbet başlattı."
            };
            conversations.set(userId, convo);
        }
        
        socket.emit('chat history', convo.messages);
        io.to('operators').emit('update conversation', convo);
    });

    socket.on('chat message from user', async ({ userId, message }) => {
        const convo = conversations.get(userId);
        if (convo) {
            convo.messages.push({ from: 'user', text: message });
            convo.lastMessage = message;
            await db.query("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES ($1, $2, $3)", [userId, 'user', message]);
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('chat message from operator', async ({ targetUserId, message }) => {
        if (socket.handshake.session.isLoggedIn) {
            const convo = conversations.get(targetUserId);
            if (convo) {
                convo.messages.push({ from: 'operator', text: message });
                await db.query("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES ($1, $2, $3)", [targetUserId, 'operator', message]);
                const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === targetUserId)?.[0];
                if (targetSocketId) io.to(targetSocketId).emit('operator reply', message);
                io.to('operators').emit('update conversation', convo);
            }
        }
    });
    
    socket.on('update user name', async ({ userId, newName }) => {
        if (socket.handshake.session.isLoggedIn) {
            const convo = conversations.get(userId);
            if (convo) {
                convo.name = newName;
                await db.query("INSERT INTO kullanici_bilgileri (kullanici_id, isim) VALUES ($1, $2) ON CONFLICT (kullanici_id) DO UPDATE SET isim = $2", [userId, newName]);
                io.to('operators').emit('update conversation', convo);
            }
        }
    });

    socket.on('end chat', ({ userId }) => {
        if (socket.handshake.session.isLoggedIn) {
            const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === userId)?.[0];
            if (targetSocketId) io.to(targetSocketId).emit('chat ended by operator');
        }
    });

    socket.on('disconnect', () => {
        console.log('Bir bağlantı kesildi:', socket.id);
        onlineUsers.delete(socket.id);
        socket.leave('operators');
    });
});

// Sunucuyu Başlatma
const HOST = '0.0.0.0';
server.listen(port, HOST, () => console.log(`${HOST}:${port} adresinde sunucu dinleniyor...`));