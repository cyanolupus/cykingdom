// Helper to encode/decode base64url
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64urlToBuffer(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/\-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray.buffer;
}

// UI Elements
const views = {
    auth: document.getElementById('auth-view'),
    main: document.getElementById('main-view'),
    profile: document.getElementById('profile-view'),
    ranking: document.getElementById('ranking-view'),
    gift: document.getElementById('gift-view')
};

function switchView(viewName) {
    Object.keys(views).forEach(key => {
        if (!views[key]) views[key] = document.getElementById(`${key}-view`);
        if (views[key]) views[key].classList.remove('active');
    });
    if (!views[viewName]) views[viewName] = document.getElementById(`${viewName}-view`);
    if (views[viewName]) views[viewName].classList.add('active');
}

function showToast(message, isError = false) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.style.color = isError ? '#ff3b30' : 'var(--text-color)';
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

async function loadUser() {
    try {
        const res = await fetch('/api/user', { credentials: 'same-origin' });
        if (res.ok) {
            currentUser = await res.json();
            const userDisplay = document.getElementById('user-display');
            if (userDisplay) userDisplay.textContent = currentUser.username;
            
            const pointsDisplay = document.getElementById('points-display');
            if (pointsDisplay) pointsDisplay.textContent = currentUser.points;
            
            if (document.getElementById('rank-display')) document.getElementById('rank-display').textContent = currentUser.rank;
            if (currentUser.icon_url) {
                document.getElementById('user-icon').src = currentUser.icon_url;
                document.getElementById('user-icon').style.display = 'block';
                const fb = document.getElementById('user-icon-fallback');
                if (fb) fb.style.display = 'none';
            } else {
                document.getElementById('user-icon').style.display = 'none';
                const fb = document.getElementById('user-icon-fallback');
                if (fb) fb.style.display = 'flex';
            }
            
            // Load gifts on main view
            loadGifts();
            
            currentPoints = currentUser.points;
            updateGachaButton();
            if (!window.location.hash.startsWith('#profile/') && !window.location.hash.startsWith('#ranking')) {
                switchView('main');
                loadHistory();
            } else {
                handleHashChange(); // Let hash router handle it
            }
        } else {
            currentUser = null;
            if (!window.location.hash.startsWith('#profile/')) {
                const text = await res.text();
                console.error('loadUser failed:', res.status, text);
                switchView('auth');
                
                // Trigger WebAuthn automatically on load
                doLogin("", "optional");
            } else {
                handleHashChange();
            }
        }
    } catch (e) {
        console.error('loadUser exception:', e);
        if (!window.location.hash.startsWith('#profile/')) {
            switchView('auth');
            doLogin("", "optional");
        } else {
            handleHashChange();
        }
    }
}

// API Calls
document.getElementById('register-btn').addEventListener('click', async () => {
    const username = document.getElementById('username-input').value;
    if (!username) return showToast('Enter a username', true);
    let admin_secret = null;
    if (username === 'admin') {
        admin_secret = prompt('管理者シークレットキーを入力してください:');
        if (!admin_secret) return showToast('キャンセルしました', true);
    }
    
    try {
        const startRes = await fetch('/api/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, admin_secret })
        });
        if (!startRes.ok) throw new Error(await startRes.text());
        
        const options = await startRes.json();
        
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        
        const credential = await navigator.credentials.create({ publicKey: options });
        
        const finishRes = await fetch('/api/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                credential_id: credential.id,
                client_data_json: bufferToBase64url(credential.response.clientDataJSON),
                attestation_object: bufferToBase64url(credential.response.attestationObject)
            })
        });
        showToast('登録が完了しました');
        loadUser();
    } catch (e) {
        showToast(e.message, true);
    }
});

let loginAbortController = null;

async function doLogin(username = "", mediation = "optional") {
    if (loginAbortController) {
        loginAbortController.abort();
    }
    loginAbortController = new AbortController();
    
    try {
        const startRes = await fetch('/api/login/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        if (!startRes.ok) throw new Error(await startRes.text());
        
        const options = await startRes.json();
        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials.forEach(cred => {
                cred.id = base64urlToBuffer(cred.id);
            });
        }
        
        // Use conditional mediation if specified, otherwise optional
        const credential = await navigator.credentials.get({ 
            publicKey: options,
            mediation: mediation,
            signal: loginAbortController.signal
        });
        
        if (!credential) return; // User cancelled or conditional UI didn't trigger
        
        const finishRes = await fetch('/api/login/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                credential_id: credential.id,
                client_data_json: bufferToBase64url(credential.response.clientDataJSON),
                authenticator_data: bufferToBase64url(credential.response.authenticatorData),
                signature: bufferToBase64url(credential.response.signature)
            })
        });
        
        if (!finishRes.ok) throw new Error(await finishRes.text());
        
        showToast('サイ🦏ンインしました');
        loadUser();
    } catch (e) {
        if (e.name !== 'NotAllowedError' && e.name !== 'AbortError') {
            console.error(e);
            showToast(e.message, true);
        }
    } finally {
        if (loginAbortController && !loginAbortController.signal.aborted) {
            loginAbortController = null;
        }
    }
}

document.getElementById('login-btn').addEventListener('click', () => {
    const username = document.getElementById('username-input').value;
    doLogin(username, "optional");
});

document.getElementById('gacha-btn').addEventListener('click', async () => {
    const res = await fetch('/api/gacha', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
        showToast(data.message || `${data.points} サイポイントを獲得！`);
        currentPoints = data.points;
        document.getElementById('points-display').textContent = data.points;
        if (data.rank !== undefined && document.getElementById('rank-display')) document.getElementById('rank-display').textContent = data.rank;
        
        if (currentUser) {
            const d = new Date();
            d.setTime(d.getTime() + 9 * 60 * 60 * 1000);
            currentUser.last_gacha_date = d.toISOString().split('T')[0];
            updateGachaButton();
        }
        
        updateJankenButtons();
    } else {
        showToast(data.message || '本日のガチャは終了しました', true);
    }
});

let currentPoints = 0;
let hasOpenMatch = false;
let isPlaying = false;
let currentUser = null;

function updateGachaButton() {
    const btn = document.getElementById('gacha-btn');
    if (!currentUser) return;
    const d = new Date();
    d.setTime(d.getTime() + 9 * 60 * 60 * 1000);
    const today = d.toISOString().split('T')[0];
    const hasRolled = currentUser.last_gacha_date === today;
    
    btn.disabled = hasRolled;
    btn.style.opacity = hasRolled ? '0.4' : '1';
    btn.style.cursor = hasRolled ? 'not-allowed' : 'pointer';
    btn.textContent = hasRolled ? "本日のガチャは終了しました" : "サイポイントガチャを引く！";
}

function updateJankenButtons() {
    const buttons = document.querySelectorAll('.play-btn');
    const disabled = isPlaying || hasOpenMatch || currentPoints < 5;
    
    buttons.forEach(btn => {
        btn.disabled = disabled;
        btn.style.opacity = disabled ? '0.4' : '1';
        btn.style.cursor = disabled ? 'not-allowed' : 'pointer';
        // Add a nice visual pop if clickable
        btn.style.transform = disabled ? 'scale(0.95)' : 'scale(1)';
    });
    
    const resultDiv = document.getElementById('janken-result');
    if (currentPoints < 5 && !hasOpenMatch && !isPlaying) {
        resultDiv.textContent = "サイポイントが不足しています";
    } else if (hasOpenMatch) {
        resultDiv.textContent = "マッチング中…";
    }
}

async function loadHistory() {
    const res = await fetch('/api/history');
    if (res.ok) {
        const matches = await res.json();
        
        hasOpenMatch = matches.some(m => m.status === 'open');
        updateJankenButtons();
        
        const list = document.getElementById('history-list');
        list.innerHTML = '';
        if (matches.length === 0) {
            list.innerHTML = '<p class="subtitle" style="font-size: 0.9rem;">直近のじゃんけん履歴はありません</p>';
            return;
        }
        
        matches.forEach(m => {
            const div = document.createElement('div');
            div.style.padding = '8px';
            div.style.borderBottom = '1px solid var(--separator)';
            div.style.fontSize = '0.9rem';
            
            const handEmoji = { 'rock': 'グー', 'paper': 'パー', 'scissors': 'チョキ' };
            const myHand = handEmoji[m.player1_hand] || m.player1_hand;
            const enemyHand = handEmoji[m.player2_hand] || m.player2_hand;
            
            if (m.status === 'open') {
                div.innerHTML = `<strong>マッチング中…</strong> (自分: ${myHand})`;
            } else {
                let resultText = '';
                if (m.result === 'win') resultText = '勝ち';
                else if (m.result === 'lose') resultText = '負け';
                else resultText = '引き分け';
                div.innerHTML = `${myHand}を出して${resultText}でした！<br>対戦相手: ${enemyHand} を出した ${m.enemy_username} さん`;
            }
            list.appendChild(div);
        });
    }
}

async function loadRanking() {
    const list = document.getElementById('ranking-list');
    if (!list) return;
    list.innerHTML = '<p>読み込み中...</p>';
    
    const res = await fetch('/api/ranking');
    if (res.ok) {
        const data = await res.json();
        const ranking = data.ranking;
        list.innerHTML = '';
        
        if (ranking.length === 0) {
            list.innerHTML = '<p class="subtitle" style="font-size: 0.9rem;">まだユーザーがいません</p>';
            return;
        }
        
        ranking.forEach((u, index) => {
            const div = document.createElement('div');
            div.style.padding = '8px';
            div.style.borderBottom = '1px solid var(--separator)';
            div.style.fontSize = '0.9rem';
            
            let rankEmoji = `${index + 1}位`;
            if (index === 0) rankEmoji = '🥇';
            if (index === 1) rankEmoji = '🥈';
            if (index === 2) rankEmoji = '🥉';
            
            const iconHtml = u.icon_url 
                ? `<img src="${u.icon_url}" style="width: 24px; height: 24px; border-radius: 50%; vertical-align: middle; margin-right: 8px; object-fit: cover;">` 
                : `<span style="display:inline-block; width: 24px; height: 24px; border-radius: 50%; background: var(--secondary-btn); vertical-align: middle; margin-right: 8px;"></span>`;
            
            div.innerHTML = `<span style="display:inline-block; width: 30px; font-weight: bold;">${rankEmoji}</span> 
                <a href="#profile/${u.username}" style="text-decoration: none; color: inherit;">
                    ${iconHtml}
                    <strong>${u.username}</strong>
                </a> 
                <span style="float: right; color: var(--text-secondary); line-height: 24px;">${u.points} 🦏</span>`;
            list.appendChild(div);
        });
    } else {
        list.innerHTML = '<p>ランキングの読み込みに失敗しました。</p>';
    }
}

document.querySelectorAll('.play-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
        if (btn.disabled) return;
        
        isPlaying = true;
        updateJankenButtons();
        
        const hand = e.target.dataset.hand;
        
        const res = await fetch('/api/play', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hand })
        });
        
        isPlaying = false;
        
        if (!res.ok) {
            updateJankenButtons();
            return showToast(await res.text(), true);
        }
        
        const data = await res.json();
        
        if (data.status === 'resolved') {
            const handEmoji = { 'rock': 'グー', 'paper': 'パー', 'scissors': 'チョキ' };
            const enemyEmoji = handEmoji[data.enemy_hand] || data.enemy_hand;
            
            const resultText = data.result === 'win' ? '勝ち' : (data.result === 'lose' ? '負け' : '引き分け');
            
            document.getElementById('janken-result').textContent = `${enemyEmoji}を出して${resultText}でした！`;
            
            // Auto update points, history
            currentPoints = data.points;
            document.getElementById('points-display').textContent = data.points;
            if (data.rank !== undefined && document.getElementById('rank-display')) document.getElementById('rank-display').textContent = data.rank;
            if (currentUser) currentUser.points = data.points;
            
            loadHistory();
        } else {
            document.getElementById('janken-result').textContent = data.message;
            loadHistory();
        }
        
        // Also refresh user points
        fetch('/api/user').then(r => r.json()).then(u => {
            if (u.points !== undefined) {
                currentPoints = u.points;
                document.getElementById('points-display').textContent = u.points;
                if (document.getElementById('rank-display')) document.getElementById('rank-display').textContent = u.rank;
                
                if (currentUser && u.last_gacha_date) {
                    currentUser.last_gacha_date = u.last_gacha_date;
                    updateGachaButton();
                }
                
                updateJankenButtons();
            }
        });
    });
});

// Periodic history refresh
setInterval(() => {
    if (document.getElementById('main-view').classList.contains('active')) {
        loadHistory();
        
        // Also refresh user points
        fetch('/api/user').then(r => r.json()).then(u => {
            if (u.points !== undefined) {
                currentPoints = u.points;
                document.getElementById('points-display').textContent = u.points;
                if (document.getElementById('rank-display')) document.getElementById('rank-display').textContent = u.rank;
                
                if (currentUser && u.last_gacha_date) {
                    currentUser.last_gacha_date = u.last_gacha_date;
                    updateGachaButton();
                }
                
                updateJankenButtons();
            }
        });
    }
}, 5000);

// Profile logic
document.getElementById('profile-btn')?.addEventListener('click', () => {
    // Navigate to own public profile link
    if (currentUser) {
        window.location.hash = `#profile/${currentUser.username}`;
    }
});

document.querySelectorAll('.back-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        window.location.hash = ''; // Clear hash
        switchView(currentUser ? 'main' : 'auth');
    });
});

document.getElementById('logout-btn')?.addEventListener('click', async () => {
    try {
        await fetch('/api/logout', { method: 'POST' });
        currentUser = null;
        currentPoints = 0;
        switchView('auth');
        showToast('ログアウトしました');
    } catch (e) {
        showToast('ログアウトに失敗しました', true);
    }
});

// Hash router
window.addEventListener('hashchange', handleHashChange);
async function handleHashChange() {
    const hash = window.location.hash;
    if (hash.startsWith('#profile/')) {
        const username = hash.substring(9);
        switchView('profile');
        loadPublicProfile(username);
    } else if (hash.startsWith('#ranking')) {
        switchView('ranking');
        loadRanking();
    } else {
        switchView(currentUser ? 'main' : 'auth');
    }
}

async function loadPublicProfile(username) {
    const list = document.getElementById('credentials-list');
    const profileTitle = document.getElementById('profile-title');
    
    if (profileTitle) {
        profileTitle.textContent = `${username} のプロフィール`;
    }
    list.innerHTML = '<p>読み込み中...</p>';
    
    const res = await fetch(`/api/profile/${username}`);
    if (res.ok) {
        const data = await res.json();
        const creds = data.credentials;
        
        // Setup profile view header
        document.getElementById('profile-username').textContent = username;
        document.getElementById('profile-points').textContent = data.points;
        if (document.getElementById('profile-rank')) document.getElementById('profile-rank').textContent = data.rank;
        
        if (data.icon_url) {
            document.getElementById('profile-icon').src = data.icon_url;
            document.getElementById('profile-icon').style.display = 'block';
            document.getElementById('profile-icon-fallback').style.display = 'none';
        } else {
            document.getElementById('profile-icon').style.display = 'none';
            document.getElementById('profile-icon-fallback').style.display = 'flex';
        }
        
        if (currentUser && currentUser.username === username) {
            document.getElementById('profile-icon-overlay').style.display = 'flex';
            document.getElementById('profile-icon-container').onclick = () => {
                document.getElementById('icon-upload').click();
            };
            document.getElementById('profile-icon-container').style.cursor = 'pointer';
            document.getElementById('profile-my-settings').style.display = 'block';
            if (username === 'admin') document.getElementById('admin-panel').style.display = 'block';
        } else {
            document.getElementById('profile-icon-overlay').style.display = 'none';
            document.getElementById('profile-icon-container').onclick = null;
            document.getElementById('profile-icon-container').style.cursor = 'default';
            document.getElementById('profile-my-settings').style.display = 'none';
            document.getElementById('admin-panel').style.display = 'none';
        }
        
        // Show points if element exists
        let html = '';
        
        if (creds.length === 0) {
            html += '<p>デバイスが登録されていません。</p>';
            list.innerHTML = html;
            return;
        }
        
        creds.forEach(c => {
            const aaguidText = c.aaguid === "00000000-0000-0000-0000-000000000000" 
                ? "00000000-0000-0000-0000-000000000000 (Passkey or generic)" 
                : c.aaguid;
                
            let algName = c.alg;
            if (algName === "Unsupported") algName = "Unknown/Unsupported";
            
            html += `
            <div style="padding: 12px; background: rgba(255,255,255,0.05); border-radius: 8px; margin-bottom: 12px; font-family: monospace; font-size: 0.85rem;">
                <div style="margin-bottom: 4px;"><strong>ID:</strong> <span style="word-break: break-all;">${c.id}</span></div>
                <div style="margin-bottom: 4px;"><strong>AAGUID:</strong> ${aaguidText}</div>
                <div style="margin-bottom: 4px;"><strong>Sign Count:</strong> ${c.sign_count}</div>
                <div style="margin-bottom: 4px;"><strong>Algorithm:</strong> ${algName}</div>
                <div style="margin-bottom: 4px;"><strong>Attestation Format:</strong> <span class="badge">${c.attestation_fmt}</span></div>
                <div style="margin-bottom: 4px;"><strong>Flags:</strong> 
                    <span class="badge" style="background: ${c.is_backed_up ? 'rgba(46, 204, 113, 0.2)' : 'rgba(255, 255, 255, 0.1)'}">${c.is_backed_up ? 'Backed Up' : 'Device Bound'}</span>
                    <span class="badge" style="background: ${c.is_user_verified ? 'rgba(46, 204, 113, 0.2)' : 'rgba(255, 255, 255, 0.1)'}">${c.is_user_verified ? 'User Verified' : 'Presence Only'}</span>
                </div>
            </div>`;
        });
        list.innerHTML = html;
    } else {
        list.innerHTML = '<p>プロフィールの読み込みに失敗しました。</p>';
    }
}


// Check if user is already logged in
loadUser();

// Gift logic
async function loadGifts() {
    const res = await fetch('/api/gift/ready');
    if (!res.ok) return;
    const gifts = await res.json();
    
    const badge = document.getElementById('gift-badge');
    if (gifts.length > 0) {
        badge.textContent = gifts.length;
        badge.style.display = 'block';
    } else {
        badge.style.display = 'none';
    }
    
    const list = document.getElementById('gift-list');
    if (gifts.length === 0) {
        list.innerHTML = '<p>プレゼントはありません</p>';
        return;
    }
    
    list.innerHTML = gifts.map(g => `
        <div style="border-bottom: 1px solid var(--separator); padding: 12px 0;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong style="display: block;">${g.description}</strong>
                    <span style="color: var(--text-secondary); font-size: 0.9em;">${g.points} 🦏</span>
                </div>
                <button class="btn primary" onclick="openGift('${g.id}')">受け取る</button>
            </div>
        </div>
    `).join('');
}

window.openGift = async (id) => {
    const res = await fetch(`/api/gift/${id}/open`, { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
        showToast(`ギフトを受け取りました！ (${data.points} 🦏)`);
        currentPoints = data.points;
        document.getElementById('points-display').textContent = data.points;
        if (document.getElementById('rank-display')) document.getElementById('rank-display').textContent = data.rank;
        loadGifts();
    } else {
        showToast(data.message || 'エラーが発生しました', true);
    }
};

// Admin panel logic
document.getElementById('admin-gift-btn')?.addEventListener('click', async () => {
    const points = parseInt(document.getElementById('admin-gift-points').value);
    const desc = document.getElementById('admin-gift-desc').value;
    if (!points || !desc) return showToast('ポイントと説明を入力してください', true);
    
    const res = await fetch('/api/admin/gift', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ points, description: desc })
    });
    if (res.ok) {
        showToast('ギフトを配布しました！');
        document.getElementById('admin-gift-points').value = '';
        document.getElementById('admin-gift-desc').value = '';
        loadGifts();
    } else {
        showToast('配布に失敗しました（権限がありません）', true);
    }
});

// Icon upload logic
document.getElementById('icon-upload')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Read and compress image
    const reader = new FileReader();
    reader.onload = (event) => {
        const img = new Image();
        img.onload = async () => {
            const canvas = document.createElement('canvas');
            const size = 128; // Resize to 128x128
            canvas.width = size;
            canvas.height = size;
            const ctx = canvas.getContext('2d');
            
            // Cover crop
            const scale = Math.max(size / img.width, size / img.height);
            const x = (size / scale - img.width) / 2;
            const y = (size / scale - img.height) / 2;
            ctx.scale(scale, scale);
            ctx.drawImage(img, x, y);
            
            // Convert to webp data uri
            const dataUri = canvas.toDataURL('image/webp', 0.8);
            
            // Upload to API
            const res = await fetch('/api/user/icon', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ icon_url: dataUri })
            });
            const data = await res.json();
            
            if (res.ok) {
                showToast('アイコンを更新しました！');
                currentUser.icon_url = data.icon_url;
                
                document.getElementById('user-icon').src = data.icon_url;
                document.getElementById('user-icon').style.display = 'block';
                const fb1 = document.getElementById('user-icon-fallback');
                if (fb1) fb1.style.display = 'none';
                
                document.getElementById('profile-icon').src = data.icon_url;
                document.getElementById('profile-icon').style.display = 'block';
                const fb2 = document.getElementById('profile-icon-fallback');
                if (fb2) fb2.style.display = 'none';
            } else {
                showToast(data.message || 'アップロードに失敗しました', true);
            }
        };
        img.src = event.target.result;
    };
    reader.readAsDataURL(file);
});

// Share Profile logic
document.getElementById('share-profile-btn')?.addEventListener('click', async () => {
    const url = window.location.href;
    const title = 'サイ王国🦏 プロフィール';
    const text = document.getElementById('profile-title')?.textContent || 'プロフィールをチェック！';
    
    if (navigator.share) {
        try {
            await navigator.share({ title, text, url });
        } catch (e) {
            console.error('Error sharing:', e);
        }
    } else {
        try {
            await navigator.clipboard.writeText(url);
            showToast('プロフィールURLをコピーしました！');
        } catch (e) {
            showToast('コピーに失敗しました', true);
        }
    }
});
