/**
 * SecureVault Enterprise - Cloudflare Edition
 * Phiên bản: 5.0 (Professional)
 * Fix lỗi: Loại bỏ màn hình "Tunnel Password", Tốc độ cao hơn.
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const os = require('os');
const https = require('https');

// ==========================================
// 1. BOOTSTRAP (Tự động kiểm tra môi trường)
// ==========================================
(async function kernelBoot() {
    console.clear();
    const log = (msg) => console.log(`\x1b[36m[SYSTEM]\x1b[0m ${msg}`);
    
    // Kiểm tra thư viện
    if (!fs.existsSync(path.join(__dirname, 'node_modules'))) {
        log('Đang cài đặt môi trường lần đầu (Sẽ mất khoảng 1-2 phút)...');
        try {
            // Cài cloudflared để bypass firewall chuyên nghiệp
            execSync('npm install express cookie-parser cloudflared', { stdio: 'inherit' });
            spawn(process.execPath, [__filename], { stdio: 'inherit' }).on('close', process.exit);
            return;
        } catch (e) { console.log('Lỗi: Cần cài Node.js trước.'); process.exit(1); }
    }
    
    startServer();
})();

// ==========================================
// 2. SERVER LOGIC
// ==========================================
function startServer() {
    const express = require('express');
    const cookieParser = require('cookie-parser');
    const crypto = require('crypto');
    const cloudflared = require('cloudflared'); // Thư viện Cloudflare

    const CONFIG = {
        PORT: 3000, 
        KEY_FILE: path.join(__dirname, 'machine.key'),
        DATA_FILE: path.join(__dirname, 'secret.enc'),
        SESSION_SECRET: crypto.randomBytes(64).toString('hex')
    };

    // --- SECURITY CORE ---
    const Security = {
        getKey: () => {
            let key;
            try {
                if (fs.existsSync(CONFIG.KEY_FILE)) {
                    key = Buffer.from(fs.readFileSync(CONFIG.KEY_FILE, 'utf8'), 'hex');
                    if (key.length !== 32) throw new Error();
                }
            } catch { key = null; }
            
            if (!key) {
                key = crypto.randomBytes(32);
                fs.writeFileSync(CONFIG.KEY_FILE, key.toString('hex'));
                if(fs.existsSync(CONFIG.DATA_FILE)) fs.unlinkSync(CONFIG.DATA_FILE);
            }
            return key;
        },
        encrypt: (text, key) => {
            if (!text) return '';
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            let e = cipher.update(text); e = Buffer.concat([e, cipher.final()]);
            return iv.toString('hex') + ':' + e.toString('hex');
        },
        decrypt: (text, key) => {
            if (!text) return '';
            try {
                const p = text.split(':');
                const iv = Buffer.from(p.shift(), 'hex');
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                let d = decipher.update(Buffer.from(p.join(':'), 'hex'));
                return Buffer.concat([d, decipher.final()]).toString();
            } catch { return ""; }
        }
    };

    const MACHINE_KEY = Security.getKey();
    const app = express();
    
    let state = {
        isOpen: false,
        otp: null,
        data: fs.existsSync(CONFIG.DATA_FILE) ? Security.decrypt(fs.readFileSync(CONFIG.DATA_FILE, 'utf8'), MACHINE_KEY) : "",
        tunnelUrl: "Đang khởi tạo kết nối...",
        publicIP: "Đang lấy..."
    };

    app.use(express.json());
    app.use(cookieParser(CONFIG.SESSION_SECRET));

    // Middleware: Phân quyền Admin/Guest dựa trên Host
    const checkRole = (req, res, next) => {
        const host = req.get('host') || '';
        // Nếu vào bằng localhost hoặc IP LAN -> Admin
        const isLocal = host.includes('localhost') || host.includes('127.0.0.1') || host.startsWith('192.168.');
        req.userRole = isLocal ? 'admin' : 'guest';
        next();
    };

    // --- API ---
    app.get('/api/status', checkRole, (req, res) => res.json({ 
        online: state.isOpen, 
        role: req.userRole, 
        otp: req.userRole === 'admin' ? state.otp : null, 
        tunnel: state.tunnelUrl,
        ip: state.publicIP
    }));

    app.post('/api/admin/toggle', checkRole, (req, res) => {
        if (req.userRole !== 'admin') return res.status(403).send();
        state.isOpen = !state.isOpen;
        state.otp = state.isOpen ? Math.floor(100000 + Math.random() * 900000).toString() : null;
        res.json({ online: state.isOpen, otp: state.otp });
    });

    app.post('/api/admin/save', checkRole, (req, res) => {
        if (req.userRole !== 'admin') return res.status(403).send();
        state.data = req.body.data;
        fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(state.data, MACHINE_KEY));
        res.json({ success: true });
    });

    app.get('/api/admin/data', checkRole, (req, res) => { 
        if (req.userRole !== 'admin') return res.status(403).send(); 
        res.json({ data: state.data }); 
    });

    app.post('/api/guest/login', (req, res) => {
        if (!state.isOpen) return res.status(503).json({ error: "Server Closed" });
        if (req.body.otp === state.otp) {
            res.cookie('auth', 'ok', { maxAge: 300000, httpOnly: true, signed: true });
            res.json({ success: true });
        } else res.status(401).json({ error: "Wrong OTP" });
    });

    app.get('/api/guest/data', (req, res) => {
        if (!state.isOpen) return res.status(503).json({ error: "Closed" });
        if (req.signedCookies.auth === 'ok') res.json({ data: state.data }); 
        else res.status(401).json({ error: "Unauthorized" });
    });

    // --- FRONTEND UI ---
    app.get('/', checkRole, (req, res) => {
        const html = `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault Pro</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script><style>.act:active{transform:scale(0.96)}</style></head><body class="bg-slate-100 h-screen flex flex-col"><div class="flex-1 flex flex-col max-w-md mx-auto w-full bg-white shadow-2xl h-full relative border-x border-slate-200"><div class="h-14 ${req.userRole==='admin'?'bg-indigo-600':'bg-teal-600'} text-white flex items-center justify-between px-4 shadow-md z-10"><h1 class="font-bold flex items-center gap-2"><i class="fa-solid fa-shield-cat"></i> SecureVault <span class="text-[10px] bg-black/20 px-2 py-1 rounded ml-1 font-mono">${req.userRole.toUpperCase()}</span></h1></div><div class="flex-1 overflow-y-auto p-4 relative bg-slate-50">${req.userRole==='admin'?`<div class="space-y-4"><div class="bg-white p-4 rounded-xl border border-indigo-100 shadow-sm"><div class="flex justify-between items-center"><span class="text-sm font-bold text-indigo-900">Trạng thái Server</span><div id="badge" class="px-3 py-1 text-xs font-bold rounded-full bg-slate-200 text-slate-500">OFFLINE</div></div><div class="mt-4"><p class="text-xs text-slate-400 uppercase font-bold mb-1">Link truy cập khách (Cloudflare)</p><div class="flex items-center gap-2"><a id="tunnel-link" href="#" target="_blank" class="text-sm font-mono text-indigo-600 font-bold truncate">Đang khởi tạo...</a><button onclick="copyLink()" class="text-slate-400 hover:text-indigo-600"><i class="fa-regular fa-copy"></i></button></div></div><div class="mt-4 pt-3 border-t border-slate-100 flex justify-between items-center"><span class="text-xs text-slate-500">Bật/Tắt Gatekeeper</span><button id="toggle" class="act w-12 h-7 bg-slate-300 rounded-full relative transition-colors"><div class="w-5 h-5 bg-white rounded-full absolute top-1 left-1 shadow transition-transform"></div></button></div></div><div id="otp-box" class="hidden bg-white p-6 rounded-xl border-2 border-dashed border-indigo-200 text-center shadow-sm"><p class="text-xs text-indigo-400 font-bold uppercase tracking-widest">MÃ OTP KHÁCH</p><div id="otp-code" class="text-5xl font-mono font-black text-indigo-600 tracking-widest mt-2 select-all">---</div></div><div class="flex flex-col h-48"><textarea id="inp" class="flex-1 p-4 bg-white border border-slate-200 rounded-xl font-mono text-sm focus:ring-2 ring-indigo-500 outline-none shadow-sm" placeholder="Nhập dữ liệu mật..."></textarea></div><button id="save" class="act w-full bg-indigo-600 text-white font-bold py-3.5 rounded-xl shadow-lg shadow-indigo-200 mt-2 hover:bg-indigo-700 transition">Lưu Dữ Liệu</button></div>`:`<div id="login" class="flex flex-col items-center justify-center h-full space-y-8 bg-white"><div class="w-20 h-20 bg-teal-50 rounded-full flex items-center justify-center text-teal-600 mb-2 shadow-inner"><i class="fa-solid fa-fingerprint text-4xl"></i></div><div class="text-center"><h2 class="text-xl font-bold text-slate-800">Xác thực quyền</h2><p class="text-sm text-slate-400">Nhập mã OTP từ máy chủ</p></div><input id="otp" type="tel" maxlength="6" class="w-48 text-center text-4xl font-mono border-b-2 border-teal-500 outline-none bg-transparent tracking-widest py-2 focus:border-teal-700 transition" placeholder="••• •••"><button id="btn-login" class="act w-64 bg-teal-600 text-white font-bold py-4 rounded-xl shadow-lg shadow-teal-200 hover:bg-teal-700 transition">MỞ KHÓA</button><p id="err" class="text-red-500 text-sm font-bold h-6"></p></div><div id="content" class="hidden h-full flex flex-col"><div class="bg-amber-50 p-4 rounded-xl flex justify-between text-amber-800 mb-4 border border-amber-100 shadow-sm"><span class="text-xs font-bold flex items-center gap-2"><i class="fa-solid fa-hourglass-half"></i> TỰ HỦY SAU</span><span id="timer" class="font-mono font-bold text-lg">05:00</span></div><div class="flex-1 bg-white border border-slate-200 rounded-xl p-4 overflow-auto relative shadow-inner"><button onclick="navigator.clipboard.writeText(document.getElementById('data').innerText);alert('Đã copy')" class="absolute top-3 right-3 w-8 h-8 flex items-center justify-center bg-slate-100 rounded-lg text-slate-500 hover:text-teal-600 hover:bg-teal-50 transition"><i class="fa-regular fa-copy"></i></button><pre id="data" class="whitespace-pre-wrap font-mono text-sm text-slate-700 select-all"></pre></div></div>`}</div></div><script>const api=axios.create({baseURL:'/api'});${req.userRole==='admin'?`const u={t:document.getElementById('toggle'),k:document.querySelector('#toggle div'),b:document.getElementById('badge'),o:document.getElementById('otp-box'),oc:document.getElementById('otp-code'),i:document.getElementById('inp'),s:document.getElementById('save'),l:document.getElementById('tunnel-link')};const r=(on,otp,link)=>{u.l.innerText=link||"Đang kết nối Cloudflare...";u.l.href=link;if(on){u.t.className="act w-12 h-7 bg-indigo-500 rounded-full relative transition-colors";u.k.style.transform="translateX(20px)";u.b.innerText="TRỰC TUYẾN";u.b.className="px-3 py-1 text-xs font-bold rounded-full bg-green-100 text-green-700";u.o.classList.remove('hidden');u.oc.innerText=otp}else{u.t.className="act w-12 h-7 bg-slate-300 rounded-full relative transition-colors";u.k.style.transform="translateX(0)";u.b.innerText="OFFLINE";u.b.className="px-3 py-1 text-xs font-bold rounded-full bg-slate-200 text-slate-500";u.o.classList.add('hidden')}};
    const poll=()=>api.get('/status').then(x=>r(x.data.online,x.data.otp,x.data.tunnel));setInterval(poll,5000);poll();api.get('/admin/data').then(x=>u.i.value=x.data.data);u.t.onclick=async()=>{const x=await api.post('/admin/toggle');poll()};u.s.onclick=async()=>{u.s.innerText="Đang lưu...";await api.post('/admin/save',{data:u.i.value});u.s.innerText="Đã lưu!";setTimeout(()=>u.s.innerText="Lưu Dữ Liệu",1000)};window.copyLink=()=>{navigator.clipboard.writeText(u.l.href);alert('Đã copy link!')};`:`const u={l:document.getElementById('login'),c:document.getElementById('content'),i:document.getElementById('otp'),b:document.getElementById('btn-login'),e:document.getElementById('err'),d:document.getElementById('data'),t:document.getElementById('timer')};const s=(txt)=>{u.l.classList.add('hidden');u.c.classList.remove('hidden');u.d.innerText=txt;let tm=300;setInterval(()=>{tm--;u.t.innerText=Math.floor(tm/60).toString().padStart(2,'0')+':'+(tm%60).toString().padStart(2,'0');if(tm<=0)location.reload()},1000)};api.get('/guest/data').then(x=>s(x.data.data)).catch(()=>{});u.b.onclick=async()=>{try{u.e.innerText="";await api.post('/guest/login',{otp:u.i.value});const x=await api.get('/guest/data');s(x.data.data)}catch{u.e.innerText="Mã OTP không đúng"}}`}</script></body></html>`;
        res.send(html);
    });

    app.listen(CONFIG.PORT, () => {
        console.log(`✅ SERVER RUNNING ON PORT ${CONFIG.PORT}`);
        
        // --- CLOUDFLARE TUNNEL INIT ---
        console.log('[SYSTEM] Đang khởi tạo Cloudflare Tunnel (Có thể mất 30s)...');
        // Sử dụng thư viện cloudflared để chạy binary
        const cfBin = cloudflared.bin;
        // Lệnh: cloudflared tunnel --url localhost:3000
        const tunnel = spawn(cfBin, ['tunnel', '--url', `http://localhost:${CONFIG.PORT}`]);

        tunnel.stderr.on('data', (data) => {
            const str = data.toString();
            // Regex để bắt link .trycloudflare.com
            const match = str.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
            if (match) {
                state.tunnelUrl = match[0];
                console.log('==================================================');
                console.log(`👉 ADMIN LINK: http://localhost:${CONFIG.PORT}`);
                console.log(`👉 GUEST LINK: ${state.tunnelUrl}`);
                console.log('   (Không cần nhập mật khẩu, không bị chặn)');
                console.log('==================================================');
            }
        });
    });
}