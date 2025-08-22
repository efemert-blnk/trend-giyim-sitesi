const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());

// Veritabanı bağlantısı ve tablo oluşturma
const db = new sqlite3.Database('./destek.db', (err) => {
    if (err) return console.error('Veritabanı hatası:', err.message);
    
    console.log('destek.db veritabanına başarıyla bağlandı.');
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS hizli_cevaplar (id INTEGER PRIMARY KEY, metin TEXT NOT NULL UNIQUE)`);
        db.run(`CREATE TABLE IF NOT EXISTS sohbet_gecmisi (id INTEGER PRIMARY KEY, kullanici_id TEXT, gonderen TEXT, mesaj TEXT, tarih DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        db.run(`CREATE TABLE IF NOT EXISTS kullanici_bilgileri (kullanici_id TEXT PRIMARY KEY, isim TEXT)`);

        // Varsayılan hızlı cevapları ekle
        db.get("SELECT COUNT(*) as count FROM hizli_cevaplar", (err, row) => {
            if (row.count === 0) {
                const defaultReplies = [
                    "Merhaba, size nasıl yardımcı olabilirim?", "İlginiz için teşekkür ederiz.", "Konuyu ilgili departmana iletiyorum, lütfen bekleyiniz.", "Farklı bir konuda yardımcı olabilir miyim?", "Ürünlerimiz hakkında detaylı bilgiye web sitemizden ulaşabilirsiniz.", "Stoklarımız güncellenmektedir, takipte kalınız."
                ];
                const stmt = db.prepare("INSERT INTO hizli_cevaplar (metin) VALUES (?)");
                defaultReplies.forEach(reply => stmt.run(reply));
                stmt.finalize();
            }
        });
    });
});

// Hızlı Cevaplar API (CRUD)
app.get('/api/hizli-cevaplar', (req, res) => {
    db.all('SELECT * FROM hizli_cevaplar ORDER BY id', [], (err, rows) => res.status(err ? 500 : 200).json(err ? { error: err.message } : rows));
});
app.post('/api/hizli-cevaplar', (req, res) => {
    const { metin } = req.body;
    if (!metin) return res.status(400).json({ error: 'Metin boş olamaz.' });
    db.run('INSERT INTO hizli_cevaplar (metin) VALUES (?)', [metin.trim()], function(err) {
        if (err) return res.status(err.code === 'SQLITE_CONSTRAINT' ? 409 : 500).json({ error: 'Bu cevap zaten mevcut.' });
        res.status(201).json({ id: this.lastID, metin: metin.trim() });
    });
});
// YENİ EKLENDİ: Hızlı Cevap Düzenleme
app.put('/api/hizli-cevaplar/:id', (req, res) => {
    const { metin } = req.body;
    if (!metin) return res.status(400).json({ error: 'Metin boş olamaz.' });
    db.run('UPDATE hizli_cevaplar SET metin = ? WHERE id = ?', [metin.trim(), req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Cevap bulunamadı.' });
        res.status(200).json({ message: 'Güncellendi.' });
    });
});
// YENİ EKLENDİ: Hızlı Cevap Silme
app.delete('/api/hizli-cevaplar/:id', (req, res) => {
    db.run('DELETE FROM hizli_cevaplar WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Cevap bulunamadı.' });
        res.status(200).json({ message: 'Silindi.' });
    });
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Canlı Destek Mantığı
let onlineUsers = new Map();
let conversations = new Map();

io.on('connection', (socket) => {
    socket.on('register as operator', () => {
        socket.join('operators');
        socket.emit('all conversations', Array.from(conversations.values()));
    });

    socket.on('user session connect', async ({ userId }) => {
        onlineUsers.set(socket.id, userId);
        let convo = conversations.get(userId);
        
        if (!convo) {
            // Kullanıcı bilgilerini ve geçmişini veritabanından çek
            const userInfo = await new Promise(resolve => db.get("SELECT isim FROM kullanici_bilgileri WHERE kullanici_id = ?", [userId], (err, row) => resolve(row)));
            const history = await new Promise(resolve => db.all("SELECT gonderen, mesaj FROM sohbet_gecmisi WHERE kullanici_id = ? ORDER BY tarih ASC", [userId], (err, rows) => resolve(rows || [])));
            
            convo = {
                id: userId,
                name: userInfo?.isim || `Kullanıcı #${userId.substring(0, 4)}`,
                messages: history.map(r => ({ from: r.gonderen, text: r.mesaj })),
                lastMessage: history.length > 0 ? history[history.length - 1].mesaj : "Yeni sohbet başlattı."
            };
            conversations.set(userId, convo);
        }
        
        socket.emit('chat history', convo.messages);
        io.to('operators').emit('update conversation', convo);
    });

    socket.on('chat message from user', ({ userId, message }) => {
        const convo = conversations.get(userId);
        if (convo) {
            const msgData = { from: 'user', text: message };
            convo.messages.push(msgData);
            convo.lastMessage = message;
            db.run("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES (?, ?, ?)", [userId, 'user', message]);
            io.to('operators').emit('update conversation', convo);
        }
    });

    socket.on('chat message from operator', ({ targetUserId, message }) => {
        const convo = conversations.get(targetUserId);
        if (convo) {
            convo.messages.push({ from: 'operator', text: message });
            db.run("INSERT INTO sohbet_gecmisi (kullanici_id, gonderen, mesaj) VALUES (?, ?, ?)", [targetUserId, 'operator', message]);
            const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === targetUserId)?.[0];
            if (targetSocketId) io.to(targetSocketId).emit('operator reply', message);
            io.to('operators').emit('update conversation', convo);
        }
    });
    
    // YENİ EKLENDİ: Kullanıcı Adını Güncelleme
    socket.on('update user name', ({ userId, newName }) => {
        const convo = conversations.get(userId);
        if (convo) {
            convo.name = newName;
            db.run("INSERT OR REPLACE INTO kullanici_bilgileri (kullanici_id, isim) VALUES (?, ?)", [userId, newName]);
            io.to('operators').emit('update conversation', convo);
        }
    });

    // YENİ EKLENDİ: Görüşmeyi Bitirme
    socket.on('end chat', ({ userId }) => {
        const targetSocketId = [...onlineUsers.entries()].find(([, uid]) => uid === userId)?.[0];
        if (targetSocketId) {
            io.to(targetSocketId).emit('chat ended by operator');
        }
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        socket.leave('operators');
    });
});

server.listen(port, () => console.log(`Backend sunucusu http://localhost:${port} adresinde çalışıyor.`));