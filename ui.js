/**
 * ui.js - Giao diện Frontend của Citadel
 * Được tách ra để server.js gọn gàng hơn.
 */

module.exports = function renderUI(isAdmin) {
    return `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault Citadel</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
        <style>
            body{font-family:sans-serif}.act:active{transform:scale(0.96)}.chk:checked+div{background-color:#eff6ff;border-color:#6366f1}
            /* Giao diện Overlay (Trình duyệt nhúng) - Đồng bộ màu sắc */
            #browser-overlay { position: fixed; inset: 0; z-index: 50; transform: translateY(100%); transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: flex; flex-direction: column; background: #f8fafc; }
            #browser-overlay.active { transform: translateY(0); }
            /* Thanh công cụ màu tối đồng bộ với style Admin */
            #browser-bar { height: 56px; background-color: #334155; display: flex; align-items: center; padding: 0 16px; color: white; justify-content: space-between; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            #browser-frame { flex: 1; border: none; width: 100%; height: 100%; background: #ffffff; }
        </style>
        </head><body class="bg-slate-100 h-screen overflow-hidden">
        
        <div class="max-w-md mx-auto h-full bg-white shadow-2xl flex flex-col relative border-x border-slate-200">
            <div class="h-14 ${isAdmin?'bg-indigo-700':'bg-emerald-600'} text-white flex items-center justify-between px-4 shadow z-10">
                <h1 class="font-bold text-lg"><i class="fa-solid fa-fort-awesome"></i> Citadel <span class="text-[10px] bg-white/20 px-2 py-0.5 rounded ml-1 font-mono">${isAdmin?'ADMIN':'GUEST'}</span></h1>
            </div>

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
                
                <div class="bg-white p-3 rounded-xl border border-slate-200 shadow-sm">
                    <div class="flex justify-between items-center mb-2"><span class="text-xs font-bold text-indigo-900"><i class="fa-solid fa-radar mr-1"></i> LAN Radar (Hybrid)</span><button id="btn-scan" class="text-[10px] bg-indigo-100 text-indigo-700 px-3 py-1 rounded-full font-bold hover:bg-indigo-200 transition">QUÉT MẠNG</button></div>
                    <div id="scan-res" class="space-y-1"><p class="text-center text-[10px] text-slate-400 italic">Nhấn Quét để tìm thiết bị...</p></div>
                </div>

                <div class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                    <div class="flex border-b border-slate-100"><button onclick="tab('txt')" id="t-txt" class="flex-1 py-3 text-sm font-bold text-indigo-600 border-b-2 border-indigo-600 bg-indigo-50">Văn bản</button><button onclick="tab('fil')" id="t-fil" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50">Files</button><button onclick="tab('cli')" id="t-cli" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50">Clients</button><button onclick="tab('req')" id="t-req" class="flex-1 py-3 text-sm font-bold text-slate-400 hover:bg-slate-50 relative">Yêu cầu <span id="req-cnt" class="hidden absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full"></span></button></div>
                    <div id="p-txt" class="p-4"><textarea id="inp-txt" class="w-full h-32 p-3 bg-slate-50 border border-slate-200 rounded font-mono text-sm outline-none focus:ring-1 ring-indigo-500" placeholder="Nội dung bảo mật..."></textarea></div>
                    <div id="p-fil" class="hidden p-4 space-y-3"><div class="flex gap-2"><label class="flex-1 bg-indigo-50 border border-indigo-100 rounded p-2 text-center cursor-pointer hover:bg-indigo-100"><input type="file" id="inp-file" class="hidden" multiple><i class="fa-solid fa-file text-indigo-500"></i> <span class="text-xs font-bold text-indigo-700">File</span></label><label class="flex-1 bg-teal-50 border border-teal-100 rounded p-2 text-center cursor-pointer hover:bg-teal-100"><input type="file" id="inp-folder" class="hidden" multiple webkitdirectory><i class="fa-solid fa-folder text-teal-500"></i> <span class="text-xs font-bold text-teal-700">Folder</span></label></div><div class="flex justify-between items-center bg-slate-100 px-2 py-1 rounded"><span class="text-xs font-bold text-slate-500">Files</span><div class="space-x-2"><button onclick="toggleAll(true)" class="text-[10px] font-bold text-indigo-600">All</button><button onclick="toggleAll(false)" class="text-[10px] font-bold text-slate-400">None</button></div></div><div id="list-files" class="space-y-1 max-h-48 overflow-y-auto"></div></div>
                    <div id="p-cli" class="hidden p-4"><div id="list-clients" class="space-y-2"></div></div>
                    <div id="p-req" class="hidden p-4"><p class="text-xs text-slate-400 font-bold uppercase mb-2">Đang chờ duyệt (Bị Kick)</p><div id="list-reqs" class="space-y-2"></div></div>
                    <div class="p-3 bg-slate-50 border-t border-slate-200 grid grid-cols-2 gap-2"><button id="btn-save" class="act bg-white border border-slate-300 text-slate-700 font-bold py-2 rounded shadow-sm text-xs">LƯU CẤU HÌNH</button><button id="btn-lock" class="act bg-rose-100 text-rose-600 font-bold py-2 rounded shadow-sm text-xs border border-rose-200"><i class="fa-solid fa-lock-open"></i> PHONG TỎA</button></div>
                </div>
            </div>` : `
            <div id="g-login" class="flex flex-col items-center justify-center h-full space-y-6"><div class="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center text-emerald-600"><i class="fa-solid fa-fingerprint text-3xl"></i></div><div class="text-center"><h2 class="font-bold text-slate-700 text-lg">Đăng nhập</h2><p class="text-xs text-slate-400">Nhập OTP</p></div><input id="g-otp" type="tel" maxlength="6" class="w-40 text-center text-3xl font-mono border-b-2 border-emerald-500 outline-none bg-transparent tracking-widest py-2" placeholder="••• •••"><button id="btn-auth" class="act w-48 py-3 bg-emerald-600 text-white font-bold rounded-lg shadow-lg shadow-emerald-200">VÀO</button><p id="g-err" class="text-red-500 text-xs font-bold h-4 text-center"></p></div>
            <div id="g-wait" class="hidden flex flex-col items-center justify-center h-full space-y-6 p-6"><div class="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center text-amber-600 animate-pulse"><i class="fa-solid fa-hourglass-half text-3xl"></i></div><div class="text-center"><h2 class="font-bold text-slate-700 text-lg">Đang chờ duyệt</h2><p class="text-xs text-slate-400 mt-1">Yêu cầu đã được gửi đến Admin</p><p class="text-2xl font-mono font-bold text-amber-500 mt-4" id="wait-time">05:00</p></div><button onclick="location.reload()" class="text-xs font-bold text-slate-400 hover:text-slate-600">Hủy yêu cầu</button></div>
            <div id="g-content" class="hidden h-full flex flex-col"><div class="bg-amber-50 px-4 py-2 flex justify-between items-center text-amber-800 border-b border-amber-100"><span class="text-xs font-bold"><i class="fa-solid fa-clock"></i> CÒN LẠI</span><span id="timer" class="font-mono font-bold">--:--</span></div><div id="g-tools" class="px-4 py-2 bg-white border-b border-slate-100 flex gap-2 hidden"><label id="btn-g-up" class="hidden flex-1 bg-indigo-50 text-indigo-700 text-xs font-bold py-2 rounded text-center cursor-pointer hover:bg-indigo-100"><input type="file" multiple class="hidden"> <i class="fa-solid fa-upload"></i> Upload</label><button id="btn-g-save" class="hidden flex-1 bg-emerald-50 text-emerald-700 text-xs font-bold py-2 rounded hover:bg-emerald-100"><i class="fa-solid fa-floppy-disk"></i> Lưu Text</button></div><div class="flex-1 overflow-auto p-4 space-y-4"><textarea id="g-txt" class="w-full h-32 p-3 bg-slate-50 border border-slate-200 rounded font-mono text-sm outline-none focus:ring-1 ring-emerald-500" readonly></textarea><div id="g-files" class="space-y-2"></div></div></div>
            `}
            </div>
        </div>

        <div id="browser-overlay">
            <div id="browser-bar">
                <button onclick="closeBrowser()" class="flex items-center gap-2 text-sm font-bold text-slate-200 hover:text-white transition">
                    <div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center"><i class="fa-solid fa-arrow-left"></i></div>
                    <span>Quay lại Citadel</span>
                </button>
                <div class="flex flex-col items-end">
                    <span id="browser-title" class="text-xs font-bold text-white">Remote Access</span>
                    <span id="browser-url" class="text-[10px] font-mono text-slate-400">Connecting...</span>
                </div>
            </div>
           <webview id="browser-frame" src="about:blank" 
    allowpopups 
    nodeintegration 
    webpreferences="contextIsolation=no, nodeIntegration=yes"
    style="flex: 1; width: 100%; height: 100%; display:inline-flex;">
</webview>
        </div>
        
        <script>
        const api = axios.create({baseURL: '/api'});
        const fmtSize = s => s<1024?s+' B':s<1024*1024?(s/1024).toFixed(1)+' KB':(s/1024/1024).toFixed(1)+' MB';

        // --- HÀM ĐIỀU KHIỂN BROWSER ---
        function openBrowser(url, hostname) {
            const ol = document.getElementById('browser-overlay');
            const fr = document.getElementById('browser-frame');
            document.getElementById('browser-title').innerText = hostname;
            document.getElementById('browser-url').innerText = url;
            fr.src = url;
            ol.classList.add('active');
        }
        function closeBrowser() {
            const ol = document.getElementById('browser-overlay');
            const fr = document.getElementById('browser-frame');
            ol.classList.remove('active');
            setTimeout(() => fr.src = "", 300); // Clear để giải phóng
        }

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
            
            // Render Radar
            if(d.radar) {
                if(d.radar.length === 0) ui.scanRes.innerHTML = '<p class="text-center text-[10px] text-slate-400 italic">Không tìm thấy thiết bị nào.</p>';
                else ui.scanRes.innerHTML = d.radar.map(p => {
                    // Nếu là máy mới (v42), hiện nút truy cập mở Browser Overlay
                    if (p.isV42) return \`<div class="bg-indigo-50 p-2 rounded border border-indigo-200 shadow-sm mt-1 animate-in fade-in slide-in-from-bottom-2 duration-300"><div class="flex justify-between items-center mb-1"><span class="text-xs font-bold text-indigo-900"><i class="fa-brands fa-apple text-indigo-600 mr-1"></i> \${p.hostname}</span><span class="text-[10px] font-mono bg-indigo-200 text-indigo-800 px-1 rounded">\${p.ip}</span></div><div class="flex justify-between items-center"><span class="text-[10px] text-indigo-500 font-bold">\${p.shareCount} Kho chia sẻ</span><button onclick="openBrowser('http://\${p.ip}:\${p.port}', '\${p.hostname}')" class="text-[10px] bg-indigo-600 text-white px-3 py-1 rounded font-bold hover:bg-indigo-700 transition shadow-sm">TRUY CẬP <i class="fa-solid fa-arrow-right"></i></button></div></div>\`;
                    // Nếu là máy cũ
                    return \`<div class="bg-slate-50 p-1 px-2 rounded border border-slate-200 flex justify-between mt-1"><span class="text-xs font-bold text-slate-700"><i class="fa-solid fa-desktop text-slate-400 mr-1"></i> \${p.hostname}</span><span class="text-[10px] font-mono text-slate-500">\${p.ip}</span></div>\`;
                }).join('');
            }
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
        ui.scanBtn.onclick = async () => { ui.scanRes.innerHTML = '<p class="text-center text-[10px] text-indigo-500 animate-pulse">Đang quét sóng...</p>'; const r = await api.post('/admin/scan'); };
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
}