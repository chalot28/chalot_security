/**
 * SecureVault Enterprise - Equilibrium (v9.0)
 * Update: Upload Folder/File riêng biệt, Auto-Kick Realtime, Cân bằng tải (Traffic Shaping).
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const os = require('os');
const dgram = require('dgram');
const { Transform } = require('stream');

// ==========================================
// 1. BOOTSTRAP (Tự động cài đặt)
// ==========================================
(async function kernelBoot() {
    console.clear();
    const log = (msg) => console.log(`\x1b[36m[SYSTEM]\x1b[0m ${msg}`);
    
    // 1. Setup thư mục
    const uploadDir = path.join(__dirname, 'uploads');
    if (fs.existsSync(uploadDir)) {
        try { fs.rmSync(uploadDir, { recursive: true, force: true }); } catch(e){}
    }
    fs.mkdirSync(uploadDir);

    // 2. Kiểm tra thư viện
    const modulesPath = path.join(__dirname, 'node_modules');
    if (!fs.existsSync(modulesPath) || !fs.existsSync(path.join(modulesPath, 'multer'))) {
        log('Đang cập nhật hệ thống lõi (v9.0)...');
        try {
            execSync('npm install express cookie-parser cloudflared multer', { stdio: 'inherit' });
            spawn(process.execPath, [__filename], { stdio: 'inherit' }).on('close', process.exit);
            return;
        } catch (e) { console.error('Lỗi: Cần cài Node.js trước.'); process.exit(1); }
    }
    
    startEquilibriumServer(uploadDir);
})();

// ==========================================
// 2. TRAFFIC SHAPER (Cân bằng băng thông)
// ==========================================
class TrafficCop {
    static activeDownloads = 0;
    
    static start() { this.activeDownloads++; }
    static end() { this.activeDownloads = Math.max(0, this.activeDownloads - 1); }

    // Tạo Stream điều tiết
    static createStream() {
        return new Transform({
            transform(chunk, encoding, callback) {
                // Nếu có > 2 người đang tải, tạo độ trễ nhân tạo để chia sẻ CPU/IO
                if (TrafficCop.activeDownloads > 2) {
                    const delay = Math.min(TrafficCop.activeDownloads * 2, 50); // Tối đa 50ms delay
                    setTimeout(() => {
                        this.push(chunk);
                        callback();
                    }, delay);
                } else {
                    // Nếu ít người, xả tối đa tốc độ
                    this.push(chunk);
                    callback();
                }
            }
        });
    }
}

// ==========================================
// 3. SERVER CORE
// ==========================================
function startEquilibriumServer(UPLOAD_DIR) {
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

    // --- MULTER (Xử lý File & Folder) ---
    const storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOAD_DIR),
        filename: (req, file, cb) => {
            // Giữ tên gốc + timestamp
            file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, Date.now() + '___' + file.originalname);
        }
    });
    // Tăng giới hạn field size để hỗ trợ upload folder lớn
    const upload = multer({ 
        storage: storage,
        limits: { fieldSize: 10 * 1024 * 1024 * 1024 } 
    });

    // --- MẠNG & MÃ HÓA ---
    const getPrimaryIP = () => {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    // Ưu tiên 192.168 (LAN) > 10.x (VPN/Corp) > 172.x (Docker/VM)
                    if(iface.address.startsWith('192.168.')) return iface.address;
                }
            }
        }
        // Fallback
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) return iface.address;
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

    let State = {
        online: false,
        otp: null,
        otpTTL: 300,
        textData: fs.existsSync(CONFIG.DATA_FILE) ? Security.decrypt(fs.readFileSync(CONFIG.DATA_FILE, 'utf8'), MASTER_KEY) : "",
        files: [],
        tunnel: "Đang khởi tạo...",
        peers: []
    };

    // --- UDP DISCOVERY (DUAL-MODE FOR VM) ---
    const udp = dgram.createSocket('udp4');
    udp.on('message', (msg, rinfo) => {
        try {
            const parsed = JSON.parse(msg.toString());
            if (parsed.type === 'SCAN' && State.online) {
                const myInfo = JSON.stringify({ type: 'PRESENCE', hostname: os.hostname(), ip: getPrimaryIP() });
                udp.send(myInfo, rinfo.port, rinfo.address, (e)=>{}); // Gửi đích danh (VM cần cái này)
                udp.send(myInfo, CONFIG.UDP_PORT, '255.255.255.255', (e)=>{}); // Gửi broadcast (App cũ cần cái này)
            }
            if (parsed.type === 'PRESENCE' && parsed.ip !== getPrimaryIP()) {
                if (!State.peers.find(p => p.ip === parsed.ip)) State.peers.push({ hostname: parsed.hostname, ip: parsed.ip });
            }
        } catch (e) {}
    });
    udp.bind(CONFIG.UDP_PORT, '0.0.0.0', () => { udp.setBroadcast(true); });

    // --- WEB SERVER ---
    const app = express();
    app.use(express.json());
    app.use(cookieParser(CONFIG.SESSION_SECRET));

    const authMiddleware = (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        req.isAdmin = (ip.includes('127.0.0.1') || ip.includes('::1'));
        next();
    };

    // API Heartbeat (Cho phép Client biết Server sống hay chết ngay lập tức)
    app.get('/api/heartbeat', (req, res) => {
        if(!State.online) return res.status(503).send('OFFLINE');
        res.send('ALIVE');
    });

    // Admin APIs
    app.get('/api/sys/info', authMiddleware, (req, res) => {
        res.json({ online: State.online, isAdmin: req.isAdmin, otp: req.isAdmin ? State.otp : null, tunnel: State.tunnel, files: State.files.length, connections: TrafficCop.activeDownloads });
    });

    app.post('/api/sys/toggle', authMiddleware, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.online = !State.online;
        if (State.online) {
            State.otpTTL = req.body.duration || 300;
            State.otp = Math.floor(100000 + Math.random() * 900000).toString();
        } else State.otp = null;
        res.json({ online: State.online, otp: State.otp });
    });

    app.post('/api/data/save', authMiddleware, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.textData = req.body.data;
        fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(State.textData, MASTER_KEY));
        res.json({ ok: true });
    });

    app.get('/api/data/get', authMiddleware, (req, res) => res.json({ data: State.textData, files: State.files }));

    // Upload (Hỗ trợ cả File và Folder)
    app.post('/api/files/upload', authMiddleware, upload.array('files'), (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        const newFiles = req.files.map(f => ({
            id: f.filename,
            name: f.originalname.replace(/^\d+___/, ''),
            size: f.size,
            path: f.path
        }));
        State.files.push(...newFiles);
        res.json({ files: State.files });
    });

    app.delete('/api/files/del/:id', authMiddleware, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        const idx = State.files.findIndex(f => f.id === req.params.id);
        if (idx > -1) { try { fs.unlinkSync(State.files[idx].path); } catch(e){} State.files.splice(idx, 1); }
        res.json({ files: State.files });
    });

    app.post('/api/sys/scan', authMiddleware, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.peers = [];
        udp.send(Buffer.from(JSON.stringify({ type: 'SCAN' })), CONFIG.UDP_PORT, '255.255.255.255');
        setTimeout(() => res.json({ peers: State.peers }), 1500);
    });

    // Guest APIs
    app.post('/api/guest/auth', (req, res) => {
        if (!State.online) return res.status(503).json({ error: "Server Closed" });
        if (req.body.otp === State.otp) {
            const maxAge = State.otpTTL === -1 ? 1000*60*60*24*365 : State.otpTTL * 1000;
            res.cookie('session_token', State.otp, { maxAge, httpOnly: true, signed: true });
            res.json({ ok: true, ttl: State.otpTTL });
        } else res.status(401).json({ error: "Wrong OTP" });
    });

    app.get('/api/guest/fetch', (req, res) => {
        if (!State.online) return res.status(503).json({ error: "Server Offline" });
        if (req.signedCookies.session_token === State.otp) res.json({ data: State.textData, files: State.files });
        else res.status(401).json({ error: "Unauthorized" });
    });

    // DOWNLOAD WITH TRAFFIC SHAPING (CÂN BẰNG TẢI)
    app.get('/api/guest/download/:id', (req, res) => {
        if (!State.online) return res.sendStatus(503);
        if (req.signedCookies.session_token !== State.otp) return res.sendStatus(401);
        
        const f = State.files.find(x => x.id === req.params.id);
        if (f && fs.existsSync(f.path)) {
            // Tăng biến đếm người dùng
            TrafficCop.start();
            
            // Stream file qua bộ điều tiết (Shaper)
            const fileStream = fs.createReadStream(f.path);
            const shaper = TrafficCop.createStream();
            
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(f.name)}"`);
            
            // File -> Shaper -> Response
            fileStream.pipe(shaper).pipe(res);

            // Khi tải xong hoặc lỗi thì giảm biến đếm
            res.on('close', () => TrafficCop.end());
            res.on('error', () => TrafficCop.end());
        } else res.sendStatus(404);
    });

    // --- FRONTEND ---
    app.get('/', authMiddleware, (req, res) => {
        const isAdmin = req.isAdmin;
        const html = `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault Equilibrium</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script><style>body{font-family:sans-serif}.act:active{transform:scale(0.96)}</style></head><body class="bg-slate-100 h-screen overflow-hidden"><div class="max-w-md mx-auto h-full bg-white shadow-2xl flex flex-col relative border-x border-slate-200"><div class="h-14 ${isAdmin?'bg-indigo-700':'bg-emerald-600'} text-white flex items-center justify-between px-4 shadow z-10"><h1 class="font-bold text-lg"><i class="fa-solid fa-scale-balanced"></i> SecureVault <span class="text-[10px] bg-white/20 px-2 py-0.5 rounded ml-1 font-mono">v9.0</span></h1></div>
        
        <div id="main-ui" class="flex-1 overflow-y-auto p-4 bg-slate-50 relative">
            ${isAdmin ? `
            <div class="space-y-4">
                <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                    <div class="flex justify-between items-center mb-4"><span class="font-bold text-slate-700">Control Center</span><span id="stt-badge" class="px-3 py-1 rounded-full text-xs font-bold bg-slate-200 text-slate-500">OFFLINE</span></div>
                    <div class="flex items-center justify-between gap-2">
                        <select id="otp-time" class="bg-slate-100 text-sm font-bold text-slate-600 py-2 px-3 rounded border-0 outline-none"><option value="120">2 Phút</option><option value="300" selected>5 Phút</option><option value="1800">30 Phút</option><option value="-1">Vô hạn</option></select>
                        <button id="btn-toggle" class="act flex-1 py-2 bg-slate-800 text-white font-bold rounded shadow hover:bg-slate-900 transition">BẬT SERVER</button>
                    </div>
                    <div id="otp-display" class="hidden mt-4 pt-4 border-t border-dashed border-slate-200 text-center"><p class="text-xs text-slate-400 font-bold uppercase">Active Connections: <span id="conn-cnt">0</span></p><p id="otp-val" class="text-4xl font-mono font-black text-indigo-600 tracking-[0.2em] mt-1 select-all">---</p></div>
                </div>

                <div class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                    <div class="flex border-b border-slate-100">
                        <button onclick="tab('txt')" id="t-txt" class="flex-1 py-3 text-sm font-bold text-indigo-600 border-b-2 border-indigo-600 bg-indigo-50">Văn bản</button>
                        <button onclick="tab('fil')" id="t-fil" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50">Files (<span id="f-cnt">0</span>)</button>
                    </div>
                    <div id="p-txt" class="p-4"><textarea id="inp-txt" class="w-full h-32 p-3 bg-slate-50 border border-slate-200 rounded font-mono text-sm outline-none focus:ring-1 ring-indigo-500" placeholder="Nội dung bảo mật..."></textarea><button id="btn-save" class="act w-full mt-2 py-3 bg-indigo-600 text-white font-bold rounded shadow hover:bg-indigo-700">LƯU DỮ LIỆU</button></div>
                    
                    <div id="p-fil" class="hidden p-4 space-y-3">
                        <div class="grid grid-cols-2 gap-3">
                            <div class="relative bg-indigo-50 border border-indigo-200 rounded-lg p-4 text-center hover:bg-indigo-100 cursor-pointer transition">
                                <input type="file" id="inp-file" class="absolute inset-0 opacity-0 cursor-pointer" multiple>
                                <i class="fa-regular fa-file text-xl text-indigo-500 mb-1"></i><p class="text-xs font-bold text-indigo-700">Gửi File Lẻ</p>
                            </div>
                            <div class="relative bg-teal-50 border border-teal-200 rounded-lg p-4 text-center hover:bg-teal-100 cursor-pointer transition">
                                <input type="file" id="inp-folder" class="absolute inset-0 opacity-0 cursor-pointer" multiple webkitdirectory>
                                <i class="fa-regular fa-folder-open text-xl text-teal-500 mb-1"></i><p class="text-xs font-bold text-teal-700">Gửi Folder</p>
                            </div>
                        </div>
                        <div id="upload-status" class="hidden text-center text-xs font-bold text-slate-400 animate-pulse">Đang tải lên... vui lòng chờ</div>
                        <div id="list-files" class="space-y-2 max-h-48 overflow-y-auto"></div>
                    </div>
                </div>

                <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
                    <div class="flex justify-between items-center"><span class="font-bold text-slate-700 text-sm"><i class="fa-solid fa-radar text-indigo-500 mr-1"></i> LAN Radar</span><button id="btn-scan" class="text-xs font-bold text-indigo-600 bg-indigo-100 px-3 py-1 rounded hover:bg-indigo-200">QUÉT</button></div>
                    <div id="scan-res" class="mt-3 space-y-2"></div>
                </div>
                 <div class="text-center"><p class="text-[10px] text-slate-400 font-bold mb-1">CLOUDFLARE LINK</p><a id="cf-link" href="#" target="_blank" class="text-xs font-mono text-indigo-400 font-bold">Waiting...</a></div>
            </div>
            ` : `
            <div id="g-login" class="flex flex-col items-center justify-center h-full space-y-6">
                <div class="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center text-emerald-600"><i class="fa-solid fa-lock text-2xl"></i></div>
                <div class="text-center"><h2 class="font-bold text-slate-700 text-lg">Xác thực quyền</h2><p class="text-xs text-slate-400">Nhập mã OTP từ máy chủ Admin</p></div>
                <input id="g-otp" type="tel" maxlength="6" class="w-40 text-center text-3xl font-mono border-b-2 border-emerald-500 outline-none bg-transparent tracking-widest py-2" placeholder="••• •••">
                <button id="btn-auth" class="act w-48 py-3 bg-emerald-600 text-white font-bold rounded-lg shadow-lg shadow-emerald-200">MỞ KHÓA</button>
                <p id="g-err" class="text-red-500 text-xs font-bold h-4"></p>
            </div>
            <div id="g-content" class="hidden h-full flex flex-col">
                <div class="bg-amber-50 px-4 py-2 flex justify-between items-center text-amber-800 border-b border-amber-100"><span class="text-xs font-bold">AUTO CLOSE</span><span id="timer" class="font-mono font-bold">--:--</span></div>
                <div class="flex-1 overflow-auto p-4 space-y-4">
                    <div class="bg-white p-3 rounded border border-slate-200 shadow-sm relative"><button onclick="navigator.clipboard.writeText(document.getElementById('g-txt').innerText);alert('Copied')" class="absolute top-2 right-2 text-slate-400 hover:text-emerald-600"><i class="fa-regular fa-copy"></i></button><pre id="g-txt" class="whitespace-pre-wrap font-mono text-sm text-slate-700"></pre></div>
                    <div id="g-files" class="space-y-2"></div>
                </div>
                <div class="p-4 bg-white border-t border-slate-200"><button onclick="location.reload()" class="w-full py-3 bg-slate-100 text-slate-500 font-bold rounded text-xs hover:bg-slate-200">ĐÓNG PHIÊN</button></div>
            </div>
            `}
        </div></div>
        
        <script>
        const api = axios.create({baseURL: '/api'});
        const fmtSize = s => s<1024?s+' B':s<1024*1024?(s/1024).toFixed(1)+' KB':(s/1024/1024).toFixed(1)+' MB';

        ${isAdmin ? `
        const ui={stt:document.getElementById('stt-badge'),btn:document.getElementById('btn-toggle'),time:document.getElementById('otp-time'),otpBox:document.getElementById('otp-display'),otpVal:document.getElementById('otp-val'),txt:document.getElementById('inp-txt'),fCnt:document.getElementById('f-cnt'),fList:document.getElementById('list-files'),cf:document.getElementById('cf-link'),scanBtn:document.getElementById('btn-scan'),scanRes:document.getElementById('scan-res'), conn:document.getElementById('conn-cnt')};
        
        const updateUI = (state) => {
            ui.stt.innerText = state.online ? "ONLINE" : "OFFLINE";
            ui.stt.className = "px-3 py-1 rounded-full text-xs font-bold " + (state.online ? "bg-green-100 text-green-700" : "bg-slate-200 text-slate-500");
            ui.btn.innerText = state.online ? "TẮT SERVER" : "BẬT SERVER";
            ui.btn.className = "act flex-1 py-2 font-bold rounded shadow transition " + (state.online ? "bg-red-500 text-white hover:bg-red-600" : "bg-slate-800 text-white hover:bg-slate-900");
            if(state.online) { ui.otpBox.classList.remove('hidden'); ui.otpVal.innerText = state.otp; ui.time.disabled=true; ui.conn.innerText = state.connections; }
            else { ui.otpBox.classList.add('hidden'); ui.time.disabled=false; }
            if(state.tunnel && !state.tunnel.includes("Lỗi")) { ui.cf.href = state.tunnel; ui.cf.innerText = state.tunnel; }
        };

        const renderFiles = (files) => {
            ui.fCnt.innerText = files.length;
            ui.fList.innerHTML = files.map(f => \`
                <div class="flex justify-between items-center bg-slate-50 p-2 rounded border border-slate-200">
                    <div class="overflow-hidden"><div class="text-xs font-bold text-slate-700 truncate">\${f.name}</div><div class="text-[10px] text-slate-400">\${fmtSize(f.size)}</div></div>
                    <button onclick="delFile('\${f.id}')" class="text-red-400 hover:bg-red-50 w-6 h-6 rounded flex items-center justify-center"><i class="fa-solid fa-trash text-xs"></i></button>
                </div>\`).join('');
        };

        setInterval(() => api.get('/sys/info').then(r => updateUI(r.data)), 2000);
        api.get('/data/get').then(r => { ui.txt.value = r.data.data; renderFiles(r.data.files); });

        ui.btn.onclick = async () => { await api.post('/sys/toggle', {duration: parseInt(ui.time.value)}); api.get('/sys/info').then(r => updateUI(r.data)); };
        document.getElementById('btn-save').onclick = async () => { await api.post('/data/save', {data: ui.txt.value}); alert('Đã lưu!'); };
        
        const handleUpload = async (e) => {
            if(!e.target.files.length) return;
            const fd = new FormData();
            for(let f of e.target.files) fd.append('files', f);
            document.getElementById('upload-status').classList.remove('hidden');
            try { await api.post('/files/upload', fd).then(r => renderFiles(r.data.files)); } catch(e){ alert('Lỗi tải file'); }
            document.getElementById('upload-status').classList.add('hidden');
            e.target.value = '';
        };
        document.getElementById('inp-file').onchange = handleUpload;
        document.getElementById('inp-folder').onchange = handleUpload;

        window.delFile = (id) => { if(confirm('Xóa?')) api.delete('/files/del/'+id).then(r => renderFiles(r.data.files)); };
        ui.scanBtn.onclick = async () => {
            ui.scanBtn.disabled = true; ui.scanBtn.innerText = "...";
            ui.scanRes.innerHTML = '<div class="text-center py-2 text-xs text-slate-400">Đang tìm kiếm...</div>';
            try {
                const res = await api.post('/sys/scan');
                ui.scanRes.innerHTML = res.data.peers.length ? res.data.peers.map(p => \`
                    <div onclick="window.open('http://\${p.ip}:3000')" class="flex justify-between items-center bg-indigo-50 p-2 rounded border border-indigo-100 cursor-pointer hover:bg-indigo-100">
                        <div><div class="text-xs font-bold text-indigo-900">\${p.hostname}</div><div class="text-[10px] text-indigo-500">\${p.ip}</div></div>
                        <i class="fa-solid fa-arrow-right text-indigo-400 text-xs"></i>
                    </div>\`).join('') : '<div class="text-center py-2 text-xs text-slate-400 italic">Không tìm thấy thiết bị nào</div>';
            } catch(e){}
            ui.scanBtn.disabled = false; ui.scanBtn.innerText = "QUÉT";
        };
        window.tab = (m) => {
            document.getElementById('p-txt').classList.toggle('hidden', m!=='txt');
            document.getElementById('p-fil').classList.toggle('hidden', m!=='fil');
        };
        ` : `
        const ui={l:document.getElementById('g-login'),c:document.getElementById('g-content'),otp:document.getElementById('g-otp'),btn:document.getElementById('btn-auth'),err:document.getElementById('g-err'),txt:document.getElementById('g-txt'),fil:document.getElementById('g-files'),tm:document.getElementById('timer')};
        let timerInt;

        // REAL-TIME HEARTBEAT CHECK
        const startHeartbeat = () => {
            setInterval(async () => {
                try {
                    await api.get('/heartbeat');
                } catch (e) {
                    // Server chết hoặc trả về 503 -> Đá user ngay lập tức
                    location.reload(); 
                }
            }, 1000); // Check mỗi 1 giây
        };

        const startTimer = (ttl) => {
            let s = parseInt(ttl);
            if(s === -1) { ui.tm.innerText = "∞"; return; }
            timerInt = setInterval(() => {
                s--;
                if(s<=0) location.reload();
                ui.tm.innerText = Math.floor(s/60).toString().padStart(2,'0') + ':' + (s%60).toString().padStart(2,'0');
            }, 1000);
        };

        ui.btn.onclick = async () => {
            try {
                ui.btn.innerText = "ĐANG XỬ LÝ..."; ui.err.innerText = "";
                const auth = await api.post('/guest/auth', {otp: ui.otp.value});
                const data = await api.get('/guest/fetch');
                
                ui.l.classList.add('hidden'); ui.c.classList.remove('hidden');
                ui.txt.innerText = data.data.data;
                ui.fil.innerHTML = data.data.files.map(f => \`
                    <div class="flex justify-between items-center bg-slate-50 p-3 rounded border border-slate-200">
                        <div class="overflow-hidden"><div class="text-sm font-bold text-slate-700 truncate">\${f.name}</div><div class="text-xs text-slate-400">\${fmtSize(f.size)}</div></div>
                        <a href="/api/guest/download/\${f.id}" class="bg-emerald-100 text-emerald-700 px-3 py-1.5 rounded text-xs font-bold hover:bg-emerald-200">TẢI</a>
                    </div>\`).join('');
                
                startTimer(auth.data.ttl);
                startHeartbeat(); // Bắt đầu theo dõi sự sống của server
            } catch(e) {
                ui.btn.innerText = "MỞ KHÓA";
                ui.err.innerText = "Mã OTP không đúng hoặc Server đóng.";
            }
        };
        `}
        </script></body></html>`;
        res.send(html);
    });

    app.listen(CONFIG.PORT, '0.0.0.0', () => {
        console.log(`✅ EQUILIBRIUM SERVER: Running on port ${CONFIG.PORT}`);
        let cfBin = null; try { cfBin = require('cloudflared').bin; } catch(e){}
        if (cfBin && fs.existsSync(cfBin)) {
            try {
                const tun = spawn(cfBin, ['tunnel', '--url', `http://localhost:${CONFIG.PORT}`]);
                tun.stderr.on('data', d => {
                    const m = d.toString().match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
                    if(m) { State.tunnel = m[0]; console.log(`🌍 INTERNET: ${m[0]}`); }
                });
            } catch(e){}
        }
    });
}