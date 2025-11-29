/**
 * SecureVault Enterprise - Citadel (v16.0 - Security Patch)
 * Fix Critical: Auth Bypass on Guest Actions, Unprotected Admin Routes.
 * Core: Session Enforcement, RBAC Strict Mode.
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const os = require('os');
const dgram = require('dgram');
const { Transform } = require('stream');

// ==========================================
// 1. BOOTSTRAP
// ==========================================
(async function kernelBoot() {
    console.clear();
    const log = (msg) => console.log(`\x1b[36m[SYSTEM]\x1b[0m ${msg}`);
    
    const uploadDir = path.join(__dirname, 'uploads');
    if (fs.existsSync(uploadDir)) {
        try { fs.rmSync(uploadDir, { recursive: true, force: true }); } catch(e){}
    }
    fs.mkdirSync(uploadDir);

    const modulesPath = path.join(__dirname, 'node_modules');
    if (!fs.existsSync(modulesPath) || !fs.existsSync(path.join(modulesPath, 'multer'))) {
        log('Đang cài đặt bản vá bảo mật Citadel v16...');
        try {
            execSync('npm install express cookie-parser cloudflared multer', { stdio: 'inherit' });
            spawn(process.execPath, [__filename], { stdio: 'inherit' }).on('close', process.exit);
            return;
        } catch (e) { console.error('Lỗi: Cần cài Node.js trước.'); process.exit(1); }
    }
    startCitadelServer(uploadDir);
})();

// ==========================================
// 2. TRAFFIC SHAPER
// ==========================================
class TrafficCop {
    static activeDownloads = 0;
    static start() { this.activeDownloads++; }
    static end() { this.activeDownloads = Math.max(0, this.activeDownloads - 1); }
    static createStream() {
        return new Transform({
            transform(chunk, encoding, callback) {
                if (TrafficCop.activeDownloads > 2) {
                    setTimeout(() => { this.push(chunk); callback(); }, Math.min(TrafficCop.activeDownloads * 2, 50));
                } else { this.push(chunk); callback(); }
            }
        });
    }
}

// ==========================================
// 3. SERVER CORE
// ==========================================
function startCitadelServer(UPLOAD_DIR) {
    const express = require('express');
    const cookieParser = require('cookie-parser');
    const crypto = require('crypto');
    const multer = require('multer');
    
    const CONFIG = {
        PORT: 3000, 
        UDP_PORT: 3001,
        KEY_FILE: path.join(__dirname, 'machine.key'),
        DATA_FILE: path.join(__dirname, 'vault.dat'),
        SESSION_SECRET: crypto.randomBytes(64).toString('hex')
    };

    const storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOAD_DIR),
        filename: (req, file, cb) => {
            file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, Date.now() + '___' + file.originalname);
        }
    });
    const upload = multer({ storage: storage, limits: { fieldSize: 10 * 1024 * 1024 * 1024 } });

    const getPrimaryIP = () => {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal && iface.address.startsWith('192.168.')) return iface.address;
            }
        }
        return '127.0.0.1';
    };

    const Security = {
        getKey: () => {
            if (fs.existsSync(CONFIG.KEY_FILE)) return Buffer.from(fs.readFileSync(CONFIG.KEY_FILE, 'utf8'), 'hex');
            const k = crypto.randomBytes(32); fs.writeFileSync(CONFIG.KEY_FILE, k.toString('hex')); return k;
        },
        encrypt: (text, key) => {
            if (!text) return '';
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            return iv.toString('hex') + ':' + Buffer.concat([cipher.update(text), cipher.final()]).toString('hex');
        },
        decrypt: (text, key) => {
            if (!text) return '';
            try {
                const p = text.split(':');
                const iv = Buffer.from(p.shift(), 'hex');
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                return Buffer.concat([decipher.update(Buffer.from(p.join(':'), 'hex')), decipher.final()]).toString();
            } catch { return ""; }
        }
    };
    const MASTER_KEY = Security.getKey();

    // --- STATE ---
    let State = {
        online: false,
        displayName: "SecureVault Citadel",
        isLocked: false, 

        otp: null,
        otpRotation: 0, 
        lastOtpGen: 0,
        serverStartTime: 0,
        serverDuration: 0,
        
        perms: { read: true, download: true, edit: false, write: false, delete: false },
        textData: fs.existsSync(CONFIG.DATA_FILE) ? Security.decrypt(fs.readFileSync(CONFIG.DATA_FILE, 'utf8'), MASTER_KEY) : "",
        files: [], 
        tunnel: "Đang khởi tạo...",
        peers: [], 
        sessions: {}, 
        blockedIPs: new Set(),
        joinRequests: {}
    };

    // Timer Loop
    setInterval(() => {
        if (!State.online) return;
        
        if (State.serverDuration !== -1) {
            const elapsed = (Date.now() - State.serverStartTime) / 1000;
            if (elapsed >= State.serverDuration) {
                State.online = false; State.otp = null; State.sessions = {}; State.isLocked = false; State.blockedIPs.clear(); State.joinRequests = {};
            }
        }
        
        if (State.otpRotation > 0) {
            if (Date.now() - State.lastOtpGen > State.otpRotation * 1000) {
                State.otp = Math.floor(100000 + Math.random() * 900000).toString();
                State.lastOtpGen = Date.now();
            }
        }

        const now = Date.now();
        for (const id in State.joinRequests) {
            if (State.joinRequests[id].expiresAt < now) delete State.joinRequests[id];
        }
    }, 1000);

    // UDP
    const udp = dgram.createSocket('udp4');
    udp.on('message', (msg, rinfo) => {
        try {
            const parsed = JSON.parse(msg.toString());
            if (parsed.type === 'SCAN' && State.online) {
                const myInfo = JSON.stringify({ type: 'PRESENCE', hostname: State.displayName, ip: getPrimaryIP() });
                udp.send(myInfo, rinfo.port, rinfo.address, (e)=>{});
                udp.send(myInfo, CONFIG.UDP_PORT, '255.255.255.255', (e)=>{});
            }
            if (parsed.type === 'PRESENCE' && parsed.ip !== getPrimaryIP()) {
                if (!State.peers.find(p => p.ip === parsed.ip)) State.peers.push({ hostname: parsed.hostname, ip: parsed.ip });
            }
        } catch (e) {}
    });
    udp.bind(CONFIG.UDP_PORT, '0.0.0.0', () => { udp.setBroadcast(true); });

    // Express
    const app = express();
    app.use(express.json());
    app.use(cookieParser(CONFIG.SESSION_SECRET));

    // Middleware: Identity Check
    const auth = (req, res, next) => {
        const isCF = req.headers['cf-ray'] || req.headers['x-forwarded-for'];
        if (isCF) { req.isAdmin = false; return next(); }
        const ip = req.socket.remoteAddress;
        req.isAdmin = (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1');
        next();
    };

    // [SECURITY FIX 1] Middleware: Enforce Permissions AND Session
    const requirePerm = (perm) => (req, res, next) => {
        // 1. Admin luôn được qua
        if (req.isAdmin) return next();

        // 2. Check Server State
        if (!State.online) return res.status(503).json({ error: "Server Offline" });
        if (State.isLocked) return res.status(403).json({ error: "Server Locked" });

        // 3. Check Feature Permission (Quyền có được bật không?)
        if (!State.perms[perm]) return res.status(403).json({ error: "Feature Disabled" });

        // 4. [CRITICAL FIX] Verify Session Token
        // Bắt buộc phải có token và token phải tồn tại trong State.sessions
        const token = req.signedCookies.session_token;
        if (!token || !State.sessions[token]) {
            return res.status(401).json({ error: "Unauthorized: No Session" });
        }

        next();
    };

    // --- ADMIN API (PROTECTED) ---
    // [SECURITY FIX 2] Tất cả Admin API phải check !req.isAdmin

    app.get('/api/admin/info', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        res.json({
            online: State.online, isLocked: State.isLocked, displayName: State.displayName,
            otp: State.otp, tunnel: State.tunnel, files: State.files,
            connections: Object.values(State.sessions), perms: State.perms,
            config: { duration: State.serverDuration, rotation: State.otpRotation },
            requests: Object.values(State.joinRequests)
        });
    });

    app.post('/api/admin/config', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        if (req.body.toggle) {
            State.online = !State.online;
            State.isLocked = false; State.blockedIPs.clear(); State.joinRequests = {};
            if (State.online) {
                State.serverStartTime = Date.now();
                State.serverDuration = parseInt(req.body.duration);
                State.otpRotation = parseInt(req.body.rotation);
                State.otp = Math.floor(100000 + Math.random() * 900000).toString();
                State.lastOtpGen = Date.now();
            } else { State.otp = null; State.sessions = {}; }
        }
        if (req.body.displayName) State.displayName = req.body.displayName;
        if (req.body.perms) State.perms = req.body.perms;
        res.json({ ok: true });
    });

    app.post('/api/admin/regen-otp', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        if (!State.online) return res.status(400).json({ error: "Server chưa bật" });
        State.otp = Math.floor(100000 + Math.random() * 900000).toString();
        State.lastOtpGen = Date.now();
        res.json({ ok: true, otp: State.otp });
    });

    app.post('/api/admin/save', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.textData = req.body.data;
        fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(State.textData, MASTER_KEY));
        if (req.body.fileStates) {
            State.files.forEach(f => { if (req.body.fileStates[f.id] !== undefined) f.isShared = req.body.fileStates[f.id]; });
        }
        res.json({ ok: true });
    });

    app.post('/api/admin/lockdown', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.isLocked = req.body.locked;
        if (State.isLocked) State.sessions = {}; 
        res.json({ ok: true, isLocked: State.isLocked });
    });

    // [SECURITY FIX 2.1] Upload File (Admin Only)
    app.post('/api/files/upload', auth, upload.array('files'), (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403); // Chặn Guest gọi API này
        const newFiles = req.files.map(f => ({ id: f.filename, name: f.originalname.replace(/^\d+___/, ''), size: f.size, path: f.path, isShared: true, uploader: 'Admin' }));
        State.files.push(...newFiles); res.json({ files: State.files });
    });

    // [SECURITY FIX 2.2] Delete File (Admin Only)
    app.delete('/api/files/del/:id', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403); // Chặn Guest gọi API này
        const idx = State.files.findIndex(f => f.id === req.params.id);
        if (idx > -1) { try { fs.unlinkSync(State.files[idx].path); } catch(e){} State.files.splice(idx, 1); }
        res.json({ files: State.files });
    });

    // [SECURITY FIX 2.3] Scan (Admin Only)
    app.post('/api/admin/scan', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403); // Chặn Guest scan
        State.peers = []; udp.send(JSON.stringify({ type: 'SCAN' }), CONFIG.UDP_PORT, '255.255.255.255');
        setTimeout(() => res.json({ peers: State.peers }), 1500);
    });

    app.post('/api/admin/kick', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        const ip = req.body.ip;
        for (let token in State.sessions) { if (State.sessions[token].ip === ip) delete State.sessions[token]; }
        State.blockedIPs.add(ip);
        res.json({ ok: true });
    });

    app.post('/api/admin/resolve', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        const { reqId, action } = req.body;
        const request = State.joinRequests[reqId];
        if (request) {
            if (action === 'APPROVE') {
                State.blockedIPs.delete(request.ip);
                const token = crypto.randomBytes(32).toString('hex');
                State.sessions[token] = { ip: request.ip, userAgent: request.userAgent };
                State.joinRequests[reqId].status = 'APPROVED';
                State.joinRequests[reqId].token = token;
            } else { delete State.joinRequests[reqId]; }
        }
        res.json({ ok: true });
    });

    // --- GUEST API ---
    app.post('/api/guest/auth', (req, res) => {
        if (!State.online) return res.status(503).json({ error: "Server Closed" });
        if (State.isLocked) return res.status(403).json({ error: "⛔ Server đang bị KHÓA." });

        if (req.body.otp === State.otp) {
            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            if (State.blockedIPs.has(ip)) {
                const reqId = crypto.randomBytes(8).toString('hex');
                State.joinRequests[reqId] = { id: reqId, ip: ip, userAgent: req.headers['user-agent'], expiresAt: Date.now() + 5 * 60 * 1000, status: 'PENDING' };
                return res.json({ status: 'WAITING', reqId: reqId, ttl: 300 });
            }
            const token = crypto.randomBytes(32).toString('hex');
            State.sessions[token] = { ip: ip, userAgent: req.headers['user-agent'] };
            res.cookie('session_token', token, { maxAge: 86400000, httpOnly: true, signed: true });
            res.json({ status: 'OK' });
        } else { res.status(401).json({ error: "Sai OTP" }); }
    });

    app.post('/api/guest/check-request', (req, res) => {
        const { reqId } = req.body;
        const reqData = State.joinRequests[reqId];
        if (!reqData) return res.json({ status: 'REJECTED' });
        if (reqData.status === 'APPROVED') {
            res.cookie('session_token', reqData.token, { maxAge: 86400000, httpOnly: true, signed: true });
            delete State.joinRequests[reqId];
            return res.json({ status: 'APPROVED' });
        }
        const remaining = Math.max(0, Math.floor((reqData.expiresAt - Date.now()) / 1000));
        res.json({ status: 'PENDING', remaining });
    });

    app.get('/api/guest/sync', (req, res) => {
        if(!State.online) return res.status(503).json({ status: 'OFFLINE' });
        if(State.isLocked) return res.status(401).json({ status: 'KICKED' });
        const token = req.signedCookies.session_token;
        if (!token || !State.sessions[token]) return res.status(401).json({ status: 'KICKED' });
        let remaining = -1;
        if (State.serverDuration !== -1) {
            remaining = Math.max(0, State.serverDuration - ((Date.now() - State.serverStartTime) / 1000));
            if (remaining === 0) return res.status(503).json({ status: 'EXPIRED' });
        }
        const visibleFiles = State.files.filter(f => f.isShared);
        res.json({ status: 'OK', data: State.textData, files: visibleFiles, remaining, perms: State.perms });
    });

    // Guest Download (Secured)
    app.get('/api/guest/download/:id', requirePerm('download'), (req, res) => {
        const f = State.files.find(x => x.id === req.params.id);
        if (f && fs.existsSync(f.path) && f.isShared) {
            TrafficCop.start();
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(f.name)}"`);
            fs.createReadStream(f.path).pipe(TrafficCop.createStream()).pipe(res).on('close',()=>TrafficCop.end());
        } else res.sendStatus(404);
    });

    // Guest Upload (Secured)
    app.post('/api/guest/upload', requirePerm('write'), upload.array('files'), (req, res) => {
        const newFiles = req.files.map(f => ({ id: f.filename, name: f.originalname.replace(/^\d+___/, ''), size: f.size, path: f.path, isShared: true, uploader: 'Guest' }));
        State.files.push(...newFiles); res.json({ ok: true });
    });

    // Guest Save Text (Secured)
    app.post('/api/guest/save', requirePerm('edit'), (req, res) => { 
        State.textData = req.body.data; 
        fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(State.textData, MASTER_KEY)); 
        res.json({ ok: true }); 
    });

    // Guest Delete File (Secured)
    app.delete('/api/guest/delete/:id', requirePerm('delete'), (req, res) => { 
        const idx = State.files.findIndex(f => f.id === req.params.id); 
        if (idx > -1) { try { fs.unlinkSync(State.files[idx].path); } catch(e){} State.files.splice(idx, 1); } 
        res.json({ ok: true }); 
    });

    // --- FRONTEND (UI Giữ nguyên) ---
    app.get('/', auth, (req, res) => {
        const isAdmin = req.isAdmin;
        const html = `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault Citadel</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script><style>body{font-family:sans-serif}.act:active{transform:scale(0.96)}.chk:checked+div{background-color:#eff6ff;border-color:#6366f1}</style></head><body class="bg-slate-100 h-screen overflow-hidden"><div class="max-w-md mx-auto h-full bg-white shadow-2xl flex flex-col relative border-x border-slate-200"><div class="h-14 ${isAdmin?'bg-indigo-700':'bg-emerald-600'} text-white flex items-center justify-between px-4 shadow z-10"><h1 class="font-bold text-lg"><i class="fa-solid fa-fort-awesome"></i> Citadel <span class="text-[10px] bg-white/20 px-2 py-0.5 rounded ml-1 font-mono">${isAdmin?'ADMIN':'GUEST'}</span></h1></div>
        
        <div id="main-ui" class="flex-1 overflow-y-auto p-4 bg-slate-50 relative">
            ${isAdmin ? `
            <div class="space-y-4">
                <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm space-y-3">
                    <div class="flex justify-between items-center"><span class="font-bold text-slate-700">Trạng Thái</span><span id="stt-badge" class="px-3 py-1 rounded-full text-xs font-bold bg-slate-200 text-slate-500">OFFLINE</span></div>
                    <div class="grid grid-cols-2 gap-2"><div><p class="text-[10px] text-slate-400 font-bold uppercase mb-1">TG Chia sẻ</p><select id="share-dur" class="w-full bg-slate-50 text-xs font-bold text-slate-700 py-2 px-2 rounded border border-slate-200 outline-none" onchange="updateOtpOptions()"><option value="300">5 Phút</option><option value="600">10 Phút</option><option value="-1">Mãi mãi</option><option value="custom">Tùy chọn...</option></select><input id="share-custom" type="number" class="hidden w-full mt-1 text-xs border rounded p-1" placeholder="Số phút"></div><div><p class="text-[10px] text-slate-400 font-bold uppercase mb-1">Đổi OTP</p><select id="otp-mode" class="w-full bg-slate-50 text-xs font-bold text-slate-700 py-2 px-2 rounded border border-slate-200 outline-none"><option value="0">Theo TG Chia sẻ</option><option value="custom">Tùy chọn</option><option value="-1" id="opt-never" disabled>Không bao giờ</option></select><input id="otp-custom" type="number" class="hidden w-full mt-1 text-xs border rounded p-1" placeholder="Số phút"></div></div>
                    <div class="bg-slate-50 p-2 rounded border border-slate-100"><p class="text-[10px] text-slate-400 font-bold uppercase mb-2">Quyền Khách</p><div class="grid grid-cols-2 gap-2 text-xs font-bold text-slate-600"><label class="flex items-center gap-2"><input type="checkbox" id="perm-download" checked> Tải xuống</label><label class="flex items-center gap-2"><input type="checkbox" id="perm-write"> Upload</label><label class="flex items-center gap-2"><input type="checkbox" id="perm-edit"> Sửa Text</label><label class="flex items-center gap-2"><input type="checkbox" id="perm-del" class="accent-red-500 text-red-500"> <span class="text-red-400">Xóa file</span></label></div></div>
                    <div><input id="disp-name" class="w-full bg-slate-50 border border-slate-200 rounded px-2 py-1 text-sm font-bold text-indigo-700 outline-none" placeholder="Tên hiển thị..." value="SecureVault"></div>
                    <button id="btn-toggle" class="act w-full py-3 bg-slate-800 text-white font-bold rounded shadow hover:bg-slate-900 transition">BẬT SERVER</button>
                    <div id="otp-display" class="hidden mt-2 pt-2 border-t border-dashed border-slate-200 text-center"><p class="text-xs text-slate-400 font-bold uppercase">Mã OTP Hiện Tại</p><p id="otp-val" class="text-4xl font-mono font-black text-indigo-600 tracking-[0.2em] mt-1 select-all">---</p><button id="btn-regen" class="mt-2 text-[10px] font-bold bg-slate-100 text-slate-500 px-3 py-1 rounded-full hover:bg-indigo-100 hover:text-indigo-600 transition"><i class="fa-solid fa-rotate mr-1"></i> ĐỔI OTP KHẨN CẤP</button></div>
                </div>
                <div class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                    <div class="flex border-b border-slate-100"><button onclick="tab('txt')" id="t-txt" class="flex-1 py-3 text-sm font-bold text-indigo-600 border-b-2 border-indigo-600 bg-indigo-50">Văn bản</button><button onclick="tab('fil')" id="t-fil" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50">Files</button><button onclick="tab('cli')" id="t-cli" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50">Clients</button><button onclick="tab('req')" id="t-req" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50 relative">Yêu cầu <span id="req-cnt" class="hidden absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full"></span></button></div>
                    <div id="p-txt" class="p-4"><textarea id="inp-txt" class="w-full h-32 p-3 bg-slate-50 border border-slate-200 rounded font-mono text-sm outline-none focus:ring-1 ring-indigo-500" placeholder="Nội dung bảo mật..."></textarea></div>
                    <div id="p-fil" class="hidden p-4 space-y-3"><div class="flex gap-2"><label class="flex-1 bg-indigo-50 border border-indigo-100 rounded p-2 text-center cursor-pointer hover:bg-indigo-100"><input type="file" id="inp-file" class="hidden" multiple><i class="fa-solid fa-file text-indigo-500"></i> <span class="text-xs font-bold text-indigo-700">File</span></label><label class="flex-1 bg-teal-50 border border-teal-100 rounded p-2 text-center cursor-pointer hover:bg-teal-100"><input type="file" id="inp-folder" class="hidden" multiple webkitdirectory><i class="fa-solid fa-folder text-teal-500"></i> <span class="text-xs font-bold text-teal-700">Folder</span></label></div><div class="flex justify-between items-center bg-slate-100 px-2 py-1 rounded"><span class="text-xs font-bold text-slate-500">Files</span><div class="space-x-2"><button onclick="toggleAll(true)" class="text-[10px] font-bold text-indigo-600">All</button><button onclick="toggleAll(false)" class="text-[10px] font-bold text-slate-400">None</button></div></div><div id="list-files" class="space-y-1 max-h-48 overflow-y-auto"></div></div>
                    <div id="p-cli" class="hidden p-4"><div id="list-clients" class="space-y-2"></div></div>
                    <div id="p-req" class="hidden p-4"><p class="text-xs text-slate-400 font-bold uppercase mb-2">Đang chờ duyệt (Bị Kick)</p><div id="list-reqs" class="space-y-2"></div></div>
                    <div class="p-3 bg-slate-50 border-t border-slate-200 grid grid-cols-2 gap-2"><button id="btn-save" class="act bg-white border border-slate-300 text-slate-700 font-bold py-2 rounded shadow-sm text-xs">LƯU CẤU HÌNH</button><button id="btn-lock" class="act bg-rose-100 text-rose-600 font-bold py-2 rounded shadow-sm text-xs border border-rose-200"><i class="fa-solid fa-lock-open"></i> PHONG TỎA</button></div>
                </div>
                 <div class="bg-white p-3 rounded-xl border border-slate-200 shadow-sm flex justify-between items-center"><span class="text-xs font-bold text-indigo-900"><i class="fa-solid fa-radar mr-1"></i> LAN Radar</span><button id="btn-scan" class="text-[10px] bg-indigo-100 text-indigo-700 px-2 py-1 rounded font-bold">QUÉT</button></div>
                 <div id="scan-res" class="space-y-1"></div>
            </div>
            ` : `
            <div id="g-login" class="flex flex-col items-center justify-center h-full space-y-6"><div class="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center text-emerald-600"><i class="fa-solid fa-fingerprint text-3xl"></i></div><div class="text-center"><h2 class="font-bold text-slate-700 text-lg">Đăng nhập</h2><p class="text-xs text-slate-400">Nhập OTP</p></div><input id="g-otp" type="tel" maxlength="6" class="w-40 text-center text-3xl font-mono border-b-2 border-emerald-500 outline-none bg-transparent tracking-widest py-2" placeholder="••• •••"><button id="btn-auth" class="act w-48 py-3 bg-emerald-600 text-white font-bold rounded-lg shadow-lg shadow-emerald-200">VÀO</button><p id="g-err" class="text-red-500 text-xs font-bold h-4 text-center"></p></div>
            <div id="g-wait" class="hidden flex flex-col items-center justify-center h-full space-y-6 p-6"><div class="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center text-amber-600 animate-pulse"><i class="fa-solid fa-hourglass-half text-3xl"></i></div><div class="text-center"><h2 class="font-bold text-slate-700 text-lg">Đang chờ duyệt</h2><p class="text-xs text-slate-400 mt-1">Yêu cầu đã được gửi đến Admin</p><p class="text-2xl font-mono font-bold text-amber-500 mt-4" id="wait-time">05:00</p></div><button onclick="location.reload()" class="text-xs font-bold text-slate-400 hover:text-slate-600">Hủy yêu cầu</button></div>
            <div id="g-content" class="hidden h-full flex flex-col"><div class="bg-amber-50 px-4 py-2 flex justify-between items-center text-amber-800 border-b border-amber-100"><span class="text-xs font-bold"><i class="fa-solid fa-clock"></i> CÒN LẠI</span><span id="timer" class="font-mono font-bold">--:--</span></div><div id="g-tools" class="px-4 py-2 bg-white border-b border-slate-100 flex gap-2 hidden"><label id="btn-g-up" class="hidden flex-1 bg-indigo-50 text-indigo-700 text-xs font-bold py-2 rounded text-center cursor-pointer hover:bg-indigo-100"><input type="file" multiple class="hidden"> <i class="fa-solid fa-upload"></i> Upload</label><button id="btn-g-save" class="hidden flex-1 bg-emerald-50 text-emerald-700 text-xs font-bold py-2 rounded hover:bg-emerald-100"><i class="fa-solid fa-floppy-disk"></i> Lưu Text</button></div><div class="flex-1 overflow-auto p-4 space-y-4"><textarea id="g-txt" class="w-full h-32 p-3 bg-slate-50 border border-slate-200 rounded font-mono text-sm outline-none focus:ring-1 ring-emerald-500" readonly></textarea><div id="g-files" class="space-y-2"></div></div></div>
            `}
        </div></div>
        
        <script>
        const api = axios.create({baseURL: '/api'});
        const fmtSize = s => s<1024?s+' B':s<1024*1024?(s/1024).toFixed(1)+' KB':(s/1024/1024).toFixed(1)+' MB';

        ${isAdmin ? `
        const ui={stt:document.getElementById('stt-badge'),btn:document.getElementById('btn-toggle'),shDur:document.getElementById('share-dur'),shCust:document.getElementById('share-custom'),otpMode:document.getElementById('otp-mode'),otpCust:document.getElementById('otp-custom'),otpNever:document.getElementById('opt-never'),name:document.getElementById('disp-name'),otpBox:document.getElementById('otp-display'),otpVal:document.getElementById('otp-val'),txt:document.getElementById('inp-txt'),fList:document.getElementById('list-files'),cList:document.getElementById('list-clients'),scanBtn:document.getElementById('btn-scan'),scanRes:document.getElementById('scan-res'), btnLock: document.getElementById('btn-lock'), rList: document.getElementById('list-reqs'), reqCnt: document.getElementById('req-cnt'), btnRegen: document.getElementById('btn-regen')};
        window.updateOtpOptions = () => { const val=ui.shDur.value; ui.shCust.classList.toggle('hidden',val!=='custom'); if(val==='-1')ui.otpNever.disabled=false; else{ui.otpNever.disabled=true;if(ui.otpMode.value==='-1')ui.otpMode.value='0'} };
        ui.otpMode.onchange = () => ui.otpCust.classList.toggle('hidden', ui.otpMode.value !== 'custom');
        let localFiles = []; let isLocked = false;
        const renderFiles=()=>{ui.fList.innerHTML=localFiles.map(f=>\`<label class="flex items-center gap-3 bg-white p-2 rounded border border-slate-100 cursor-pointer hover:border-indigo-300 transition select-none"><input type="checkbox" class="chk hidden" \${f.isShared?'checked':''} onchange="toggleFile('\${f.id}')"><div class="w-5 h-5 rounded border-2 border-slate-300 flex items-center justify-center text-white text-xs peer-checked:bg-indigo-600 peer-checked:border-indigo-600"><i class="fa-solid fa-check"></i></div><div class="flex-1 min-w-0"><div class="text-xs font-bold text-slate-700 truncate">\${f.name}</div><div class="text-[10px] text-slate-400">\${fmtSize(f.size)} \${f.uploader === 'Guest' ? '(Khách)' : ''}</div></div><button onclick="delFile('\${f.id}', event)" class="w-6 h-6 flex items-center justify-center text-red-300 hover:text-red-500"><i class="fa-solid fa-trash"></i></button></label>\`).join('')};
        const updateUI = (d) => {
            ui.stt.innerText = d.online ? "ONLINE" : "OFFLINE"; ui.stt.className = "px-3 py-1 rounded-full text-xs font-bold " + (d.online ? "bg-green-100 text-green-700" : "bg-slate-200 text-slate-500");
            ui.btn.innerText = d.online ? "TẮT SERVER" : "BẬT SERVER"; ui.btn.className = "act w-full py-3 font-bold rounded shadow transition " + (d.online ? "bg-red-500 text-white hover:bg-red-600" : "bg-slate-800 text-white hover:bg-slate-900");
            [ui.shDur, ui.shCust, ui.otpMode, ui.otpCust, ui.name].forEach(e => e.disabled = d.online);
            if(d.online) { ui.otpBox.classList.remove('hidden'); ui.otpVal.innerText = d.otp; } else { ui.otpBox.classList.add('hidden'); }
            isLocked = d.isLocked; ui.btnLock.innerHTML = isLocked ? '<i class="fa-solid fa-lock"></i> ĐÃ PHONG TỎA (MỞ)' : '<i class="fa-solid fa-lock-open"></i> PHONG TỎA'; ui.btnLock.className = "act font-bold py-2 rounded shadow-sm text-xs border " + (isLocked ? "bg-red-600 text-white border-red-700" : "bg-rose-100 text-rose-600 border-rose-200");
            ui.cList.innerHTML = d.connections.map(c => \`<div class="flex justify-between items-center bg-slate-50 p-2 rounded border border-slate-200"><div><div class="text-xs font-bold text-slate-700">\${c.ip}</div></div><button onclick="kickUser('\${c.ip}')" class="text-[10px] font-bold bg-red-100 text-red-600 px-2 py-1 rounded hover:bg-red-200">KICK</button></div>\`).join('');
            if(d.requests && d.requests.length) { ui.reqCnt.classList.remove('hidden'); ui.rList.innerHTML = d.requests.map(r => { const timeLeft = Math.max(0, Math.floor((r.expiresAt - Date.now())/1000)); return \`<div class="bg-amber-50 border border-amber-200 p-2 rounded"><div class="flex justify-between mb-1"><span class="text-xs font-bold text-slate-700">\${r.ip}</span><span class="text-[10px] font-mono text-amber-600">\${Math.floor(timeLeft/60)}:\${(timeLeft%60).toString().padStart(2,'0')}</span></div><div class="flex gap-2"><button onclick="resolveReq('\${r.id}', 'APPROVE')" class="flex-1 bg-green-500 text-white text-[10px] font-bold py-1 rounded hover:bg-green-600">DUYỆT</button><button onclick="resolveReq('\${r.id}', 'REJECT')" class="flex-1 bg-red-400 text-white text-[10px] font-bold py-1 rounded hover:bg-red-500">XÓA</button></div></div>\`; }).join(''); } else { ui.reqCnt.classList.add('hidden'); ui.rList.innerHTML = '<p class="text-center text-xs text-slate-400 italic">Không có yêu cầu nào</p>'; }
        };

        setInterval(() => api.get('/admin/info').then(r => { updateUI(r.data); localFiles=r.data.files; renderFiles(); }), 2000);
        api.get('/admin/info').then(r => { const p = r.data.perms; document.getElementById('perm-download').checked = p.download; document.getElementById('perm-write').checked = p.write; document.getElementById('perm-edit').checked = p.edit; document.getElementById('perm-del').checked = p.delete; });
        ui.btn.onclick = async () => { let dur = ui.shDur.value === 'custom' ? parseInt(ui.shCust.value)*60 : parseInt(ui.shDur.value); let rot = ui.otpMode.value === 'custom' ? parseInt(ui.otpCust.value) : parseInt(ui.otpMode.value); const perms = { download: document.getElementById('perm-download').checked, write: document.getElementById('perm-write').checked, edit: document.getElementById('perm-edit').checked, delete: document.getElementById('perm-del').checked }; await api.post('/admin/config', { toggle: true, duration: dur, rotation: rot, displayName: ui.name.value, perms: perms }); };
        ui.btnLock.onclick = async () => { await api.post('/admin/lockdown', { locked: !isLocked }); alert(isLocked ? 'Đã MỞ khóa.' : 'Đã PHONG TỎA.'); };
        ui.btnRegen.onclick = async () => { if(!confirm('Bạn có chắc muốn đổi OTP ngay lập tức?')) return; const r = await api.post('/admin/regen-otp'); ui.otpVal.innerText = r.data.otp; };
        document.getElementById('btn-save').onclick = () => { const fs = {}; localFiles.forEach(f => fs[f.id] = f.isShared); api.post('/admin/save', { data: ui.txt.value, fileStates: fs }); };
        const handleUpload = (e) => { if(!e.target.files.length) return; const fd = new FormData(); for(let f of e.target.files) fd.append('files', f); api.post('/files/upload', fd).then(r => { localFiles = r.data.files; renderFiles(); }); e.target.value = ''; };
        document.getElementById('inp-file').onchange = handleUpload; document.getElementById('inp-folder').onchange = handleUpload;
        window.toggleFile = (id) => { const f = localFiles.find(x=>x.id===id); if(f) f.isShared = !f.isShared; }; window.toggleAll = (v) => { localFiles.forEach(f => f.isShared = v); renderFiles(); }; window.delFile = (id, e) => { e.preventDefault(); if(confirm('Xóa?')) api.delete('/files/del/'+id); }; window.kickUser = (ip) => api.post('/admin/kick', {ip}); window.resolveReq = (id, act) => api.post('/admin/resolve', {reqId: id, action: act});
        ui.scanBtn.onclick = async () => { ui.scanRes.innerHTML = '...'; const r = await api.post('/admin/scan'); ui.scanRes.innerHTML = r.data.peers.map(p=>\`<div class="flex justify-between bg-indigo-50 p-1 px-2 rounded border border-indigo-100 text-[10px]"><span class="font-bold">\${p.hostname}</span><span>\${p.ip}</span></div>\`).join(''); };
        window.tab = (m) => ['txt','fil','cli','req'].forEach(x => { document.getElementById('p-'+x).classList.toggle('hidden', m!==x); document.getElementById('t-'+x).classList.toggle('text-indigo-600', m===x); document.getElementById('t-'+x).classList.toggle('border-indigo-600', m===x); });
        ` : `
        const ui={l:document.getElementById('g-login'),w:document.getElementById('g-wait'),c:document.getElementById('g-content'),otp:document.getElementById('g-otp'),btn:document.getElementById('btn-auth'),err:document.getElementById('g-err'),txt:document.getElementById('g-txt'),fil:document.getElementById('g-files'),tm:document.getElementById('timer'), wt:document.getElementById('wait-time'), tools:document.getElementById('g-tools'), btnUp:document.getElementById('btn-g-up'), btnSave:document.getElementById('btn-g-save')};
        let waitInt = null;
        const startWaiting = (reqId, ttl) => {
            ui.l.classList.add('hidden'); ui.w.classList.remove('hidden'); let s = ttl;
            waitInt = setInterval(async () => {
                s--; ui.wt.innerText = Math.floor(s/60).toString().padStart(2,'0') + ':' + (s%60).toString().padStart(2,'0');
                if(s%2===0) { const res = await api.post('/guest/check-request', {reqId}); if(res.data.status === 'APPROVED') { clearInterval(waitInt); ui.w.classList.add('hidden'); sync(); } else if(res.data.status === 'REJECTED') { location.reload(); } }
                if(s<=0) location.reload();
            }, 1000);
        };
        const sync = async () => {
            try {
                const res = await api.get('/guest/sync');
                if (res.data.status === 'OK') {
                    ui.l.classList.add('hidden'); ui.w.classList.add('hidden'); ui.c.classList.remove('hidden');
                    const perms = res.data.perms; const data = res.data;
                    if(ui.txt.value !== data.data && document.activeElement !== ui.txt) ui.txt.value = data.data; ui.txt.readOnly = !perms.edit;
                    let html = data.files.map(f => {
                        let btns = ''; if(perms.download) btns += \`<a href="/api/guest/download/\${f.id}" class="bg-emerald-100 text-emerald-700 px-3 py-1.5 rounded text-xs font-bold hover:bg-emerald-200">TẢI</a>\`; if(perms.delete) btns += \`<button onclick="delFile('\${f.id}')" class="ml-2 bg-red-100 text-red-700 px-2 py-1.5 rounded text-xs font-bold hover:bg-red-200">XÓA</button>\`;
                        return \`<div class="flex justify-between items-center bg-slate-50 p-3 rounded border border-slate-200"><div class="min-w-0"><div class="text-sm font-bold text-slate-700 truncate">\${f.name}</div><div class="text-xs text-slate-400">\${fmtSize(f.size)}</div></div><div class="flex">\${btns}</div></div>\`;
                    }).join('');
                    if(ui.fil.innerHTML !== html) ui.fil.innerHTML = html;
                    if(perms.write || perms.edit) ui.tools.classList.remove('hidden'); else ui.tools.classList.add('hidden'); if(perms.write) ui.btnUp.classList.remove('hidden'); else ui.btnUp.classList.add('hidden'); if(perms.edit) ui.btnSave.classList.remove('hidden'); else ui.btnSave.classList.add('hidden');
                    const rem = data.remaining; if (rem === -1) ui.tm.innerText = "∞"; else if (rem === 0) location.reload(); else ui.tm.innerText = Math.floor(rem/60).toString().padStart(2,'0') + ':' + Math.floor(rem%60).toString().padStart(2,'0');
                } else { if(ui.c.classList.contains('hidden')) return; location.reload(); }
            } catch (e) { if(ui.c.classList.contains('hidden')) return; location.reload(); }
        };
        setInterval(sync, 1000); sync();
        ui.btn.onclick = async () => { try { ui.btn.innerText = "..."; ui.err.innerText = ""; const res = await api.post('/guest/auth', {otp: ui.otp.value}); if(res.data.status === 'WAITING') { startWaiting(res.data.reqId, res.data.ttl); } else { sync(); ui.btn.innerText = "VÀO"; } } catch(e) { ui.btn.innerText = "VÀO"; ui.err.innerText = e.response?.data?.error || "Lỗi"; } };
        ui.btnSave.onclick = async () => { await api.post('/guest/save', {data: ui.txt.value}); alert('Đã lưu!'); };
        ui.btnUp.querySelector('input').onchange = async (e) => { if(!e.target.files.length) return; const fd = new FormData(); for(let f of e.target.files) fd.append('files', f); await api.post('/guest/upload', fd); e.target.value = ''; };
        window.delFile = (id) => { if(confirm('Xóa file này?')) api.delete('/guest/delete/'+id); };
        `}
        </script></body></html>`;
        res.send(html);
    });

    app.listen(CONFIG.PORT, '0.0.0.0', () => {
        console.log(`✅ CITADEL SERVER: Running on port ${CONFIG.PORT}`);
        let cfBin = null; try { cfBin = require('cloudflared').bin; } catch(e){}
        if (cfBin && fs.existsSync(cfBin)) { try { spawn(cfBin, ['tunnel', '--url', `http://localhost:${CONFIG.PORT}`]); } catch(e){} }
    });
}