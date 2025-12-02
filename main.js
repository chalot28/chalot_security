/**
 * main.js - Citadel Launcher (Fixed Permissions)
 */
const { app, BrowserWindow, shell, Menu, session } = require('electron');
const path = require('path');
const startServer = require('./server'); 

let mainWindow;
const PORT = 3000;

// Tắt hoàn toàn bảo mật Site Isolation để tránh lỗi iframe/webview trong mạng LAN
app.commandLine.appendSwitch('disable-site-isolation-trials');
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('allow-insecure-localhost', 'true');

Menu.setApplicationMenu(null);

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 480,
        height: 850,
        title: "Citadel Hybrid",
        webPreferences: { 
            nodeIntegration: true,
            nodeIntegrationInSubFrames: true, // Cho phép iframe/webview dùng Node
            contextIsolation: false,
            webviewTag: true, // Bắt buộc để dùng thẻ <webview>
            webSecurity: false, // Tắt bảo mật CORS
            allowRunningInsecureContent: true
        }
    });

    // Giả lập User Agent giống Chrome thật để tránh bị nhận diện là bot
    mainWindow.webContents.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    mainWindow.loadURL(`http://localhost:${PORT}`);

    // Xử lý link ngoài
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if(url.startsWith('http')) shell.openExternal(url);
        return { action: 'deny' };
    });

    // Cấp quyền tự động cho mọi yêu cầu (Camera, Mic, Clipboard...)
    mainWindow.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
        callback(true);
    });

    mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
    const userDataPath = app.getPath('userData');
    startServer(userDataPath, PORT, () => {
        createWindow();
    });

    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });