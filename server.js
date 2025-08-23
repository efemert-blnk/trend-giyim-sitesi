const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('pg');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 3000;

// Veritabanı Bağlantısı
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

db.connect(err => {
    if (err) return console.error('Veritabanına bağlanılamadı', err.stack);
    console.log('PostgreSQL veritabanına başarıyla bağlandı.');
    createTables();
});

app.use(bodyParser.json());
app.use(cors());

// Token Ayarları
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || "12345";
const JWT_SECRET = process.env.JWT_SECRET || 'cok-gizli-bir-anahtar';

// Statik Dosyaları Sunma
app.use(express.static(path.join(__dirname, 'public')));

// Tabloları Oluşturma Fonksiyonu
const createTables = async () => {
    try {
        await db.query(`CREATE TABLE IF NOT EXISTS yorumlar (id SERIAL PRIMARY KEY, ad TEXT NOT NULL, mesaj TEXT NOT NULL, puan INTEGER NOT NULL, tarih TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await db.query(`CREATE TABLE IF NOT EXISTS onay_bekleyen_yorumlar (id SERIAL PRIMARY KEY, ad TEXT NOT NULL, mesaj TEXT NOT NULL, puan INTEGER NOT NULL, tarih TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await db.query(`CREATE TABLE IF NOT EXISTS hizli_cevaplar (id SERIAL PRIMARY KEY, metin TEXT NOT NULL UNIQUE)`);
        await db.query(`CREATE TABLE IF NOT EXISTS sohbet_gecmisi (id SERIAL PRIMARY KEY, kullanici_id TEXT, gonderen TEXT, mesaj TEXT, tarih TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)`);
        await db.query(`CREATE TABLE IF NOT EXISTS kullanici_bilgileri (kullanici_id TEXT PRIMARY KEY, isim TEXT, sohbet_durumu TEXT DEFAULT 'acik')`);
        
        await db.query(`
            CREATE TABLE IF NOT EXISTS kullanicilar (
                id SERIAL PRIMARY KEY,
                ad TEXT NOT NULL,
                soyad TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                sifre_hash TEXT NOT NULL,
                ban_durumu BOOLEAN DEFAULT FALSE,
                olusturma_tarihi TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        `);

        const yorumRes = await db.query("SELECT COUNT(*) as count FROM yorumlar");
        if (yorumRes.rows[0].count == 0) {
            const defaultYorumlar = [
                { ad: 'Ahmet Yılmaz', mesaj: 'Takım elbisenin kalitesi ve duruşu harika, tam istediğim gibi oldu. Teşekkürler!', puan: 5 },
                { ad: 'Murat Kaya', mesaj: 'Çorumdaki en iyi erkek giyim mağazası diyebilirim. Personel çok ilgili.', puan: 5 },
            ];
            const query = 'INSERT INTO yorumlar (ad, mesaj, puan) VALUES ($1, $2, $3)';
            for (const yorum of defaultYorumlar) {
                await db.query(query, [yorum.ad, yorum.mesaj, yorum.puan]);
            }
        }
    } catch (err) {
        if (err.code !== '42P07' && err.code !== '42701') console.error("Tablo oluşturma hatası:", err.message);
    }
};

// --- HESAP YÖNETİMİ API'LARI ---
app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === OPERATOR_PASSWORD) {
        const token = jwt.sign({ isOperator: true }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({ token });
    } else {
        res.status(401).json({ message: 'Hatalı şifre.' });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { ad, soyad, email, sifre } = req.body;
        if (!ad || !soyad || !email || !sifre) return res.status(400).json({ message: 'Lütfen tüm alanları doldurun.' });
        
        const mevcutKullanici = await db.query('SELECT * FROM kullanicilar WHERE email = $1', [email]);
        if (mevcutKullanici.rows.length > 0) return res.status(409).json({ message: 'Bu e-posta adresi zaten kullanılıyor.' });
        
        const salt = await bcrypt.genSalt(10);
        const sifreHash = await bcrypt.hash(sifre, salt);
        const yeniKullaniciRes = await db.query('INSERT INTO kullanicilar (ad, soyad, email, sifre_hash) VALUES ($1, $2, $3, $4) RETURNING *', [ad, soyad, email, sifreHash]);
        const yeniKullanici = yeniKullaniciRes.rows[0];
        const token = jwt.sign({ userId: yeniKullanici.id, email: yeniKullanici.email, isOperator: false }, JWT_SECRET, { expiresIn: '8h' });
        
        res.status(201).json({
            message: 'Hesabınız başarıyla oluşturuldu ve giriş yapıldı!',
            token: token,
            kullanici: { id: yeniKullanici.id, ad: yeniKullanici.ad, email: yeniKullanici.email }
        });
    } catch (error) {
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, sifre } = req.body;
        if (!email || !sifre) return res.status(400).json({ message: 'Lütfen tüm alanları doldurun.' });
        
        const kullaniciRes = await db.query('SELECT * FROM kullanicilar WHERE email = $1', [email]);
        if (kullaniciRes.rows.length === 0) return res.status(401).json({ message: 'E-posta veya şifre hatalı.' });
        
        const kullanici = kullaniciRes.rows[0];
        if (kullanici.ban_durumu) return res.status(403).json({ message: 'Bu hesap askıya alınmıştır.' });

        const dogruSifre = await bcrypt.compare(sifre, kullanici.sifre_hash);
        if (!dogruSifre) return res.status(401).json({ message: 'E-posta veya şifre hatalı.' });
        
        const token = jwt.sign({ userId: kullanici.id, email: kullanici.email, isOperator: false }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({
            message: 'Giriş başarılı!',
            token: token,
            kullanici: { id: kullanici.id, ad: kullanici.ad, email: kullanici.email }
        });
    } catch (error) {
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// --- OPERATÖR YETKİLENDİRME ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err || !decoded.isOperator) return res.status(403).json({ message: 'Yetkisiz işlem.' });
            req.user = decoded;
            next();
        });
    } else {
        res.status(401).json({ message: 'Yetkilendirme tokenı bulunamadı.' });
    }
};

app.get('/operator.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'operator.html'));
});

// --- YORUM API'LARI ---
app.get('/api/yorumlar', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM yorumlar ORDER BY tarih DESC');
        res.json({ yorumlar: result.rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/yorumlar', async (req, res) => {
    try {
        const { ad, mesaj, puan } = req.body;
        if (!ad || !mesaj || !puan) return res.status(400).json({ error: 'Tüm alanlar zorunludur.' });
        await db.query('INSERT INTO onay_bekleyen_yorumlar (ad, mesaj, puan) VALUES ($1, $2, $3)', [ad, mesaj, puan]);
        res.status(201).json({ message: 'Yorumunuz başarıyla alınmıştır. Onaylandıktan sonra yayınlanacaktır.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/onay-bekleyen-yorumlar', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM onay_bekleyen_yorumlar ORDER BY tarih ASC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/yorumlar/onayla/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const yorumRes = await db.query('SELECT * FROM onay_bekleyen_yorumlar WHERE id = $1', [id]);
        if (yorumRes.rows.length === 0) return res.status(404).json({ error: 'Yorum bulunamadı.' });
        const yorum = yorumRes.rows[0];
        await db.query('INSERT INTO yorumlar (ad, mesaj, puan, tarih) VALUES ($1, $2, $3, $4)', [yorum.ad, yorum.mesaj, yorum.puan, yorum.tarih]);
        await db.query('DELETE FROM onay_bekleyen_yorumlar WHERE id = $1', [id]);
        res.status(200).json({ message: 'Yorum onaylandı.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/onay-bekleyen-yorumlar/:id', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('DELETE FROM onay_bekleyen_yorumlar WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Yorum bulunamadı.'});
        res.status(200).json({ message: 'Yorum silindi.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- HIZLI CEVAP API'LARI ---
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

// --- ADMİN PANELİ İŞLEMLERİ ---
app.get('/api/admin/users', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('SELECT id, ad, soyad, email, olusturma_tarihi, ban_durumu FROM kullanicilar ORDER BY olusturma_tarihi DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/users/:id/ban', authMiddleware, async (req, res) => {
    try {
        await db.query('UPDATE kullanicilar SET ban_durumu = TRUE WHERE id = $1', [req.params.id]);
        res.status(200).json({ message: 'Kullanıcı banlandı.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/users/:id/unban', authMiddleware, async (req, res) => {
    try {
        await db.query('UPDATE kullanicilar SET ban_durumu = FALSE WHERE id = $1', [req.params.id]);
        res.status(200).json({ message: 'Kullanıcının banı kaldırıldı.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- CANLI DESTEK (Socket.IO) ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", credentials: true } });
let onlineUsers = new Map();
let conversations = new Map();

io.on('connection', (socket) => {
    socket.isOperator = false;
    const operatorToken = socket.handshake.auth.token;
    if (operatorToken) {
        jwt.verify(operatorToken, JWT_SECRET, (err, decoded) => {
            if (err || !decoded.isOperator) return;
            socket.isOperator = true;
            socket.join('operators');
            socket.emit('all conversations', Array.from(conversations.values()));
        });
    }

    socket.on('user session connect', async ({ userId, userToken }) => {
        if (userToken) {
            try {
                const decoded = jwt.verify(userToken, JWT_SECRET);
                if (decoded.userId) {
                    const userRes = await db.query('SELECT ban_durumu FROM kullanicilar WHERE id = $1', [decoded.userId]);
                    if (userRes.rows.length > 0 && userRes.rows[0].ban_durumu) {
                        socket.emit('user banned');
                        return;
                    }
                }
            } catch (err) {}
        }
        
        onlineUsers.set(socket.id, userId);
        let convo = conversations.get(userId);
        if (!convo) {
            let name = `Kullanıcı #${userId.substring(0, 4)}`;
            if(userToken){
                try {
                    const decoded = jwt.verify(userToken, JWT_SECRET);
                    const userRes = await db.query('SELECT ad, soyad FROM kullanicilar WHERE id = $1', [decoded.userId]);
                    if(userRes.rows.length > 0) name = `${userRes.rows[0].ad} ${userRes.rows[0].soyad}`;
                } catch(e){}
            }
            const historyRes = await db.query("SELECT gonderen, mesaj FROM sohbet_gecmisi WHERE kullanici_id = $1 ORDER BY tarih ASC", [userId]);
            convo = { id: userId, name, messages: historyRes.rows.map(r => ({ from: r.gonderen, text: r.mesaj })), status: 'acik' };
            conversations.set(userId, convo);
        }
        
        if (convo.status === 'kapali') {
            socket.emit('chat history locked');
        } else {
            socket.emit('chat history', convo.messages);
        }
        io.to('operators').emit('update conversation', convo);
    });

    socket.on('chat message from user', async ({ userId, message }) => {
        const convo = conversations.get(userId);
        if (convo) {
            if (convo.status === 'kapali') {
                convo.status = 'acik';
            }
            convo.messages.push({ from: 'user', text: message, tarih: new Date() });
            await db.query("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES ($1, $2, $3)", [userId, 'user', message]);
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('chat message from operator', async ({ targetUserId, message }) => {
        if (socket.isOperator) {
            const convo = conversations.get(targetUserId);
            if (convo) {
                convo.messages.push({ from: 'operator', text: message, tarih: new Date() });
                await db.query("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES ($1, $2, $3)", [targetUserId, 'operator', message]);
                const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === targetUserId)?.[0];
                if (targetSocketId) io.to(targetSocketId).emit('operator reply', message);
                io.to('operators').emit('update conversation', convo);
            }
        }
    });
    
    socket.on('end chat', async ({ userId }) => {
        if (socket.isOperator) {
            const convo = conversations.get(userId);
            if (convo) {
                convo.status = 'kapali';
            }
            const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === userId)?.[0];
            if (targetSocketId) io.to(targetSocketId).emit('chat ended by operator');
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
    });
});

const HOST = '0.0.0.0';
server.listen(port, HOST, () => console.log(`${HOST}:${port} adresinde sunucu dinleniyor...`));