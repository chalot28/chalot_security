/**
 * SecureVault Enterprise - Citadel (Ultimate Hybrid Edition)
 * server.js - Cleaned Version (UI Separated)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const dgram = require('dgram');
const { Transform } = require('stream');
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const multer = require('multer');
const axios = require('axios');
let bonjour; try { bonjour = require('bonjour')(); } catch (e) {}

// IMPORT UI
const renderUI = require('./ui');

// ==========================================
// 1. TRAFFIC SHAPER (Logic Cũ - Giữ nguyên)
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
// 2. SERVER CORE FUNCTION
// ==========================================
function startCitadelServer(userDataPath, port, onReady) {
    
    // --- PATH CONFIG ---
    const UPLOAD_DIR = path.join(userDataPath, 'citadel_data', 'uploads');
    const CONFIG = {
        PORT: port, 
        UDP_PORT: 3001,
        KEY_FILE: path.join(userDataPath, 'citadel_data', 'machine.key'),
        DATA_FILE: path.join(userDataPath, 'citadel_data', 'vault.dat'),
        SESSION_SECRET: crypto.randomBytes(64).toString('hex')
    };

    if (!fs.existsSync(path.join(userDataPath, 'citadel_data'))) fs.mkdirSync(path.join(userDataPath, 'citadel_data'), { recursive: true });
    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

    const log = (msg) => console.log(`\x1b[36m[CITADEL]\x1b[0m ${msg}`);

    // --- MULTER ---
    const storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOAD_DIR),
        filename: (req, file, cb) => {
            file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
            cb(null, Date.now() + '___' + file.originalname);
        }
    });
    const upload = multer({ storage: storage, limits: { fieldSize: 10 * 1024 * 1024 * 1024 } });

    // --- HELPERS ---
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

    // --- STATE MANAGEMENT ---
    let State = {
        online: false, displayName: "SecureVault Citadel", isLocked: false, 
        otp: null, otpRotation: 0, lastOtpGen: 0, serverStartTime: 0, serverDuration: 0,
        perms: { read: true, download: true, edit: false, write: false, delete: false },
        textData: fs.existsSync(CONFIG.DATA_FILE) ? Security.decrypt(fs.readFileSync(CONFIG.DATA_FILE, 'utf8'), MASTER_KEY) : "",
        files: [], 
        peers: [], // UDP Peers (Cũ)
        v42Nodes: [], // Bonjour Peers (Mới)
        sessions: {}, blockedIPs: new Set(), joinRequests: {}
    };

    try {
        const existingFiles = fs.readdirSync(UPLOAD_DIR);
        State.files = existingFiles.map(f => ({ id: f, name: f.replace(/^\d+___/, ''), size: fs.statSync(path.join(UPLOAD_DIR, f)).size, path: path.join(UPLOAD_DIR, f), isShared: true, uploader: 'System' }));
    } catch(e) {}

    // --- TIMERS ---
    setInterval(() => {
        if (!State.online) return;
        if (State.serverDuration !== -1) {
            const elapsed = (Date.now() - State.serverStartTime) / 1000;
            if (elapsed >= State.serverDuration) { State.online = false; State.otp = null; State.sessions = {}; State.isLocked = false; State.blockedIPs.clear(); State.joinRequests = {}; }
        }
        if (State.otpRotation > 0 && Date.now() - State.lastOtpGen > State.otpRotation * 1000) {
            State.otp = Math.floor(100000 + Math.random() * 900000).toString();
            State.lastOtpGen = Date.now();
        }
        const now = Date.now();
        for (const id in State.joinRequests) { if (State.joinRequests[id].expiresAt < now) delete State.joinRequests[id]; }
    }, 1000);

    // --- 3. HYBRID DISCOVERY SYSTEM ---
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
                if (!State.peers.find(p => p.ip === parsed.ip)) State.peers.push({ hostname: parsed.hostname, ip: parsed.ip, type: 'LEGACY' });
            }
        } catch (e) {}
    });
    try { udp.bind(CONFIG.UDP_PORT, '0.0.0.0', () => { udp.setBroadcast(true); }); } catch(e) { log("UDP Port Busy"); }

    const scanBonjour = () => {
        if (!bonjour) return;
        State.v42Nodes = [];
        bonjour.find({ type: 'http' }, async (service) => {
            if (service.port === CONFIG.PORT && (service.addresses.includes(getPrimaryIP()) || service.host === os.hostname())) return;
            const nodeIP = service.addresses.find(ip => ip.startsWith('192.168.')) || service.addresses[0];
            if (!nodeIP) return;
            try {
                const checkUrl = `http://${nodeIP}:${service.port}/api/shares`;
                const res = await axios.get(checkUrl, { timeout: 1500 });
                if (res.data && res.data.list) {
                    const nodeInfo = { hostname: service.name, ip: nodeIP, port: service.port, type: 'V42', shares: res.data.list };
                    if (!State.v42Nodes.find(n => n.ip === nodeIP && n.port === service.port)) State.v42Nodes.push(nodeInfo);
                }
            } catch (err) {}
        });
    };

    // --- EXPRESS SETUP ---
    const app = express();
    app.use(express.json());
    app.use(cookieParser(CONFIG.SESSION_SECRET));

    const auth = (req, res, next) => {
        const isCF = req.headers['cf-ray'] || req.headers['x-forwarded-for'];
        if (isCF) { req.isAdmin = false; return next(); }
        const ip = req.socket.remoteAddress;
        req.isAdmin = (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1');
        next();
    };

    const requirePerm = (perm) => (req, res, next) => {
        if (req.isAdmin) return next();
        if (!State.online) return res.status(503).json({ error: "Server Offline" });
        if (State.isLocked) return res.status(403).json({ error: "Server Locked" });
        if (!State.perms[perm]) return res.status(403).json({ error: "Feature Disabled" });
        const token = req.signedCookies.session_token;
        if (!token || !State.sessions[token]) return res.status(401).json({ error: "Unauthorized: No Session" });
        next();
    };

    // --- APIs ---
    
    app.get('/api/admin/info', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        const radarData = [
            ...State.peers.map(p => ({...p, isV42: false})),
            ...State.v42Nodes.map(n => ({hostname: n.hostname, ip: n.ip, port: n.port, isV42: true, shareCount: n.shares.length}))
        ];
        res.json({
            online: State.online, isLocked: State.isLocked, displayName: State.displayName,
            otp: State.otp, tunnel: State.tunnel, files: State.files,
            connections: Object.values(State.sessions), perms: State.perms,
            config: { duration: State.serverDuration, rotation: State.otpRotation },
            requests: Object.values(State.joinRequests),
            radar: radarData
        });
    });

    app.post('/api/admin/scan', auth, (req, res) => {
        if (!req.isAdmin) return res.sendStatus(403);
        State.peers = []; udp.send(JSON.stringify({ type: 'SCAN' }), CONFIG.UDP_PORT, '255.255.255.255');
        scanBonjour();
        setTimeout(() => {
             const radarData = [
                ...State.peers.map(p => ({...p, isV42: false})),
                ...State.v42Nodes.map(n => ({hostname: n.hostname, ip: n.ip, port: n.port, isV42: true, shareCount: n.shares.length}))
            ];
            res.json({ peers: radarData });
        }, 2000);
    });

    app.post('/api/admin/config', auth, (req, res) => { if(!req.isAdmin) return res.sendStatus(403); if(req.body.toggle) { State.online = !State.online; if(State.online) { State.serverStartTime=Date.now(); State.serverDuration=parseInt(req.body.duration); State.otpRotation=parseInt(req.body.rotation); State.otp=Math.floor(100000+Math.random()*900000).toString(); State.lastOtpGen=Date.now(); } else { State.otp=null; State.sessions={}; } } if(req.body.displayName) State.displayName = req.body.displayName; if(req.body.perms) State.perms = req.body.perms; res.json({ok: true}); });
    app.post('/api/admin/regen-otp', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); if (!State.online) return res.status(400).json({ error: "Server chưa bật" }); State.otp = Math.floor(100000 + Math.random() * 900000).toString(); State.lastOtpGen = Date.now(); res.json({ ok: true, otp: State.otp }); });
    app.post('/api/admin/save', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); State.textData = req.body.data; fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(State.textData, MASTER_KEY)); if (req.body.fileStates) { State.files.forEach(f => { if (req.body.fileStates[f.id] !== undefined) f.isShared = req.body.fileStates[f.id]; }); } res.json({ ok: true }); });
    app.post('/api/admin/lockdown', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); State.isLocked = req.body.locked; if (State.isLocked) State.sessions = {}; res.json({ ok: true, isLocked: State.isLocked }); });
    app.post('/api/files/upload', auth, upload.array('files'), (req, res) => { if (!req.isAdmin) return res.sendStatus(403); const newFiles = req.files.map(f => ({ id: f.filename, name: f.originalname.replace(/^\d+___/, ''), size: f.size, path: f.path, isShared: true, uploader: 'Admin' })); State.files.push(...newFiles); res.json({ files: State.files }); });
    app.delete('/api/files/del/:id', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); const idx = State.files.findIndex(f => f.id === req.params.id); if (idx > -1) { try { fs.unlinkSync(State.files[idx].path); } catch(e){} State.files.splice(idx, 1); } res.json({ files: State.files }); });
    app.post('/api/admin/kick', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); const ip = req.body.ip; for (let token in State.sessions) { if (State.sessions[token].ip === ip) delete State.sessions[token]; } State.blockedIPs.add(ip); res.json({ ok: true }); });
    app.post('/api/admin/resolve', auth, (req, res) => { if (!req.isAdmin) return res.sendStatus(403); const { reqId, action } = req.body; if (State.joinRequests[reqId]) { if (action === 'APPROVE') { State.blockedIPs.delete(State.joinRequests[reqId].ip); const token = crypto.randomBytes(32).toString('hex'); State.sessions[token] = { ip: State.joinRequests[reqId].ip, userAgent: State.joinRequests[reqId].userAgent }; State.joinRequests[reqId].status = 'APPROVED'; State.joinRequests[reqId].token = token; } else { delete State.joinRequests[reqId]; } } res.json({ ok: true }); });

    app.post('/api/guest/auth', (req, res) => { if (!State.online) return res.status(503).json({ error: "Server Closed" }); if (State.isLocked) return res.status(403).json({ error: "⛔ Server đang bị KHÓA." }); if (req.body.otp === State.otp) { const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress; if (State.blockedIPs.has(ip)) { const reqId = crypto.randomBytes(8).toString('hex'); State.joinRequests[reqId] = { id: reqId, ip: ip, userAgent: req.headers['user-agent'], expiresAt: Date.now() + 5 * 60 * 1000, status: 'PENDING' }; return res.json({ status: 'WAITING', reqId: reqId, ttl: 300 }); } const token = crypto.randomBytes(32).toString('hex'); State.sessions[token] = { ip: ip, userAgent: req.headers['user-agent'] }; res.cookie('session_token', token, { maxAge: 86400000, httpOnly: true, signed: true }); res.json({ status: 'OK' }); } else { res.status(401).json({ error: "Sai OTP" }); } });
    app.post('/api/guest/check-request', (req, res) => { const { reqId } = req.body; const reqData = State.joinRequests[reqId]; if (!reqData) return res.json({ status: 'REJECTED' }); if (reqData.status === 'APPROVED') { res.cookie('session_token', reqData.token, { maxAge: 86400000, httpOnly: true, signed: true }); delete State.joinRequests[reqId]; return res.json({ status: 'APPROVED' }); } const remaining = Math.max(0, Math.floor((reqData.expiresAt - Date.now()) / 1000)); res.json({ status: 'PENDING', remaining }); });
    app.get('/api/guest/sync', (req, res) => { if(!State.online) return res.status(503).json({ status: 'OFFLINE' }); if(State.isLocked) return res.status(401).json({ status: 'KICKED' }); const token = req.signedCookies.session_token; if (!token || !State.sessions[token]) return res.status(401).json({ status: 'KICKED' }); let remaining = -1; if (State.serverDuration !== -1) { remaining = Math.max(0, State.serverDuration - ((Date.now() - State.serverStartTime) / 1000)); if (remaining === 0) return res.status(503).json({ status: 'EXPIRED' }); } const visibleFiles = State.files.filter(f => f.isShared); res.json({ status: 'OK', data: State.textData, files: visibleFiles, remaining, perms: State.perms }); });
    app.get('/api/guest/download/:id', requirePerm('download'), (req, res) => { const f = State.files.find(x => x.id === req.params.id); if (!f || !fs.existsSync(f.path) || !f.isShared) return res.sendStatus(404); const head = { 'Content-Length': fs.statSync(f.path).size, 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${encodeURIComponent(f.name)}"` }; res.writeHead(200, head); TrafficCop.start(); fs.createReadStream(f.path).pipe(TrafficCop.createStream()).pipe(res).on('close', () => TrafficCop.end()); });
    app.post('/api/guest/upload', requirePerm('write'), upload.array('files'), (req, res) => { const newFiles = req.files.map(f => ({ id: f.filename, name: f.originalname.replace(/^\d+___/, ''), size: f.size, path: f.path, isShared: true, uploader: 'Guest' })); State.files.push(...newFiles); res.json({ ok: true }); });
    app.post('/api/guest/save', requirePerm('edit'), (req, res) => { State.textData = req.body.data; fs.writeFileSync(CONFIG.DATA_FILE, Security.encrypt(State.textData, MASTER_KEY)); res.json({ ok: true }); });
    app.delete('/api/guest/delete/:id', requirePerm('delete'), (req, res) => { const idx = State.files.findIndex(f => f.id === req.params.id); if (idx > -1) { try { fs.unlinkSync(State.files[idx].path); } catch(e){} State.files.splice(idx, 1); } res.json({ ok: true }); });

    // --- FRONTEND UI (Đã tách ra UI.js) ---
    app.get('/', auth, (req, res) => {
        const html = renderUI(req.isAdmin);
        res.send(html);
    });

    const serverInstance = app.listen(CONFIG.PORT, '0.0.0.0', () => {
        if (onReady) onReady();
        if(bonjour) bonjour.publish({ name: State.displayName, type: 'http', port: CONFIG.PORT });
    });
    return serverInstance;
}

module.exports = startCitadelServer;