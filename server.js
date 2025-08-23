const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const { Client } = require('pg');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // YENİ EKLENDİ

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

// Giriş (Login) API ve Token Ayarları
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
        
        // YENİ EKLENDİ: Kullanıcılar tablosu
        await db.query(`
            CREATE TABLE IF NOT EXISTS kullanicilar (
                id SERIAL PRIMARY KEY,
                ad TEXT NOT NULL,
                soyad TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                sifre_hash TEXT NOT NULL,
                olusturma_tarihi TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Zengin içerik için varsayılan yorumları ekle
        const yorumRes = await db.query("SELECT COUNT(*) as count FROM yorumlar");
        if (yorumRes.rows[0].count == 0) {
            const defaultYorumlar = [
                { ad: 'Ahmet Yılmaz', mesaj: 'Takım elbisenin kalitesi ve duruşu harika, tam istediğim gibi oldu. Teşekkürler!', puan: 5 },
                { ad: 'Murat Kaya', mesaj: 'Çorumdaki en iyi erkek giyim mağazası diyebilirim. Personel çok ilgili.', puan: 5 },
                { ad: 'Caner Biçer', mesaj: 'Gömlek ve pantolon aldım, kumaşları çok kaliteli. Fiyatlar da makul.', puan: 4 },
            ];
            const query = 'INSERT INTO yorumlar (ad, mesaj, puan) VALUES ($1, $2, $3)';
            for (const yorum of defaultYorumlar) {
                await db.query(query, [yorum.ad, yorum.mesaj, yorum.puan]);
            }
            console.log("Varsayılan onaylanmış yorumlar eklendi.");
        }

    } catch (err) {
        if (err.code !== '42P07' && err.code !== '42701') console.error("Tablo oluşturma hatası:", err.message);
    }
};

// --- HESAP YÖNETİMİ API'LARI ---

// OPERATÖR GİRİŞİ
app.post('/login', (req, res) => {
    const { password } = req.body;
    if (password === OPERATOR_PASSWORD) {
        const token = jwt.sign({ isOperator: true }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({ token });
    } else {
        res.status(401).json({ message: 'Hatalı şifre.' });
    }
});

// YENİ EKLENDİ: KULLANICI KAYIT (REGISTER) API
app.post('/api/register', async (req, res) => {
    try {
        const { ad, soyad, email, sifre } = req.body;

        if (!ad || !soyad || !email || !sifre) {
            return res.status(400).json({ message: 'Lütfen tüm alanları doldurun.' });
        }

        const mevcutKullanici = await db.query('SELECT * FROM kullanicilar WHERE email = $1', [email]);
        if (mevcutKullanici.rows.length > 0) {
            return res.status(409).json({ message: 'Bu e-posta adresi zaten kullanılıyor.' });
        }

        const salt = await bcrypt.genSalt(10);
        const sifreHash = await bcrypt.hash(sifre, salt);

        const yeniKullanici = await db.query(
            'INSERT INTO kullanicilar (ad, soyad, email, sifre_hash) VALUES ($1, $2, $3, $4) RETURNING id, email',
            [ad, soyad, email, sifreHash]
        );

        res.status(201).json({ 
            message: 'Hesabınız başarıyla oluşturuldu!',
            kullanici: yeniKullanici.rows[0]
        });

    } catch (error) {
        console.error("Kayıt hatası:", error);
        res.status(500).json({ message: 'Sunucu hatası. Lütfen daha sonra tekrar deneyin.' });
    }
});

// YENİ EKLENDİ: KULLANICI GİRİŞ (LOGIN) API
app.post('/api/login', async (req, res) => {
    try {
        const { email, sifre } = req.body;

        if (!email || !sifre) {
            return res.status(400).json({ message: 'Lütfen tüm alanları doldurun.' });
        }

        const kullanici = await db.query('SELECT * FROM kullanicilar WHERE email = $1', [email]);
        if (kullanici.rows.length === 0) {
            return res.status(401).json({ message: 'E-posta veya şifre hatalı.' });
        }

        const dogruSifre = await bcrypt.compare(sifre, kullanici.rows[0].sifre_hash);
        if (!dogruSifre) {
            return res.status(401).json({ message: 'E-posta veya şifre hatalı.' });
        }

        const token = jwt.sign(
            { 
                userId: kullanici.rows[0].id,
                email: kullanici.rows[0].email,
                isOperator: false 
            }, 
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.status(200).json({
            message: 'Giriş başarılı!',
            token: token,
            kullanici: {
                id: kullanici.rows[0].id,
                ad: kullanici.rows[0].ad,
                email: kullanici.rows[0].email
            }
        });

    } catch (error) {
        console.error("Giriş hatası:", error);
        res.status(500).json({ message: 'Sunucu hatası. Lütfen daha sonra tekrar deneyin.' });
    }
});


// --- OPERATÖR İÇİN TOKEN DOĞRULAMA ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err || !decoded.isOperator) {
                return res.status(403).json({ message: 'Geçersiz veya süresi dolmuş token.' });
            }
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


// --- YORUM API UÇ NOKTALARI ---
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


// --- YORUM YÖNETİM API'LARI (OPERATÖR İÇİN) ---
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

app.put('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const { metin } = req.body;
        const result = await db.query('UPDATE hizli_cevaplar SET metin = $1 WHERE id = $2', [metin.trim(), req.params.id]);
        if (result.rowCount > 0) res.status(200).json({ message: 'Güncellendi.' });
        else res.status(404).json({ error: 'Cevap bulunamadı.'});
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/hizli-cevaplar/:id', authMiddleware, async (req, res) => {
    try {
        const result = await db.query('DELETE FROM hizli_cevaplar WHERE id = $1', [req.params.id]);
        if (result.rowCount > 0) res.status(200).json({ message: 'Silindi.' });
        else res.status(404).json({ error: 'Cevap bulunamadı.'});
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- CANLI DESTEK (Socket.IO) ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", credentials: true } });

let onlineUsers = new Map();
let conversations = new Map();

io.on('connection', (socket) => {
    console.log('Yeni bir bağlantı:', socket.id);
    socket.isOperator = false;

    const token = socket.handshake.auth.token;
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err || !decoded.isOperator) {
                return;
            }
            socket.isOperator = true;
            console.log(`Doğrulanmış operatör bağlandı: ${socket.id}`);
            socket.join('operators');
            socket.emit('all conversations', Array.from(conversations.values()));
        });
    }

    socket.on('user session connect', async ({ userId }) => {
        onlineUsers.set(socket.id, userId);
        let convo = conversations.get(userId);
        if (!convo) {
            const userInfoRes = await db.query("SELECT isim, sohbet_durumu FROM kullanici_bilgileri WHERE kullanici_id = $1", [userId]);
            const historyRes = await db.query("SELECT gonderen, mesaj FROM sohbet_gecmisi WHERE kullanici_id = $1 ORDER BY tarih ASC", [userId]);
            convo = { id: userId, name: userInfoRes.rows[0]?.isim || `Kullanıcı #${userId.substring(0, 4)}`, messages: historyRes.rows.map(r => ({ from: r.gonderen, text: r.mesaj })), lastMessage: "Sohbete bağlandı.", status: userInfoRes.rows[0]?.sohbet_durumu || 'acik' };
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
                await db.query("UPDATE kullanici_bilgileri SET sohbet_durumu = 'acik' WHERE kullanici_id = $1", [userId]);
            }
            convo.messages.push({ from: 'user', text: message });
            convo.lastMessage = message;
            await db.query("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES ($1, $2, $3)", [userId, 'user', message]);
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('chat message from operator', async ({ targetUserId, message }) => {
        if (socket.isOperator) {
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
        if (socket.isOperator) {
            const convo = conversations.get(userId);
            if (convo) {
                convo.name = newName;
                await db.query("INSERT INTO kullanici_bilgileri (kullanici_id, isim) VALUES ($1, $2) ON CONFLICT (kullanici_id) DO UPDATE SET isim = $2", [userId, newName]);
                io.to('operators').emit('update conversation', convo);
            }
        }
    });

    socket.on('end chat', async ({ userId }) => {
        if (socket.isOperator) {
            const convo = conversations.get(userId);
            if (convo) {
                convo.status = 'kapali';
                await db.query("INSERT INTO kullanici_bilgileri (kullanici_id, sohbet_durumu) VALUES ($1, 'kapali') ON CONFLICT (kullanici_id) DO UPDATE SET sohbet_durumu = 'kapali'", [userId]);
            }
            const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === userId)?.[0];
            if (targetSocketId) io.to(targetSocketId).emit('chat ended by operator');
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('disconnect', () => {
        console.log('Bir bağlantı kesildi:', socket.id);
        onlineUsers.delete(socket.id);
    });
});

const HOST = '0.0.0.0';
server.listen(port, HOST, () => console.log(`${HOST}:${port} adresinde sunucu dinleniyor...`));