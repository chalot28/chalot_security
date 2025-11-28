const API = 'http://localhost:3000';

// 1. Khởi động: Lấy IP và Load Data
window.onload = async () => {
    // Lấy IP của máy này
    const res = await fetch('/my-info');
    const data = await res.json();
    document.getElementById('my-ip').innerText = data.ip;
    
    // Tải dữ liệu hiện tại
    loadVault();
    
    // Bắt đầu quét mạng
    setInterval(loadPeers, 3000);
};

// 2. Chức năng Vault
async function loadVault() {
    const res = await fetch('/my-data');
    const data = await res.json();
    document.getElementById('vault-content').value = data.raw_data;
}

async function saveVault() {
    const text = document.getElementById('vault-content').value;
    await fetch('/save-data', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ text })
    });
    alert("Dữ liệu đã được mã hóa và lưu vào ổ cứng!");
}

// 3. Chức năng Gửi (Sinh OTP)
async function generateOTP() {
    const res = await fetch('/start-share', { method: 'POST' });
    const data = await res.json();
    document.getElementById('otp-screen').innerText = data.otp;
}

// 4. Chức năng Quét Mạng (Peers)
async function loadPeers() {
    const res = await fetch('/peers');
    const peers = await res.json();
    const select = document.getElementById('peer-list');
    
    // Giữ lại giá trị đang chọn nếu có
    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Chọn thiết bị gửi --</option>';
    
    for (const [ip, info] of Object.entries(peers)) {
        const option = document.createElement('option');
        option.value = ip;
        option.text = `Thiết bị: ${ip}`;
        select.appendChild(option);
    }
    if (currentVal) select.value = currentVal;
}

// 5. Chức năng Nhận (Kết nối & Pull)
async function pullData() {
    const targetIp = document.getElementById('peer-list').value;
    const otp = document.getElementById('otp-input').value;
    const statusEl = document.getElementById('transfer-status');

    if (!targetIp || !otp) {
        alert("Vui lòng chọn thiết bị và nhập OTP!");
        return;
    }

    statusEl.innerText = "Đang kết nối & xác thực...";
    
    try {
        const res = await fetch('/trigger-pull', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ targetIp, otp })
        });
        const data = await res.json();
        
        if (res.ok) {
            statusEl.innerText = "Thành công!";
            alert(data.message);
            loadVault(); // Tải lại dữ liệu mới nhận lên màn hình
            document.getElementById('otp-input').value = ""; // Xóa OTP
        } else {
            statusEl.innerText = "Lỗi: " + data.error;
        }
    } catch (e) {
        statusEl.innerText = "Lỗi kết nối mạng!";
    }
}