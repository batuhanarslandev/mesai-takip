// Donanım Tabanlı Parmak İzi (Hardware + WebGL + Canvas Fingerprinting)
async function generateHardwareFingerprint() {
  const components = [];

  // 1. Ekran ve Donanım Özellikleri
  components.push(screen.width + 'x' + screen.height + 'x' + screen.colorDepth);
  components.push(window.devicePixelRatio || 1);
  components.push(navigator.hardwareConcurrency || 'unknown');
  components.push(navigator.language || '');
  components.push(Intl.DateTimeFormat().resolvedOptions().timeZone || '');

  // 2. WebGL / GPU Renderer Kimliği
  try {
    const canvasGl = document.createElement('canvas');
    const gl = canvasGl.getContext('webgl') || canvasGl.getContext('experimental-webgl');
    if (gl) {
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (debugInfo) {
        components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
        components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
      }
    }
  } catch (_) {}

  // 3. 2D Canvas Çizim İmzası (GPU ve font işleme farkı)
  try {
    const canvas2d = document.createElement('canvas');
    canvas2d.width = 240;
    canvas2d.height = 60;
    const ctx = canvas2d.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px "Arial", "Helvetica", sans-serif';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('KurumMesaiSecurity#120', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('KurumMesaiSecurity#120', 4, 17);
      components.push(canvas2d.toDataURL());
    }
  } catch (_) {}

  // 4. Bileşenleri Birleştir ve SHA-256 Hash Al
  const rawString = components.join('###');
  const msgBuffer = new TextEncoder().encode(rawString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return 'hwfp_' + hashHex;
}

const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const UI = {
  alert: (msg, isError = true) => {
    const el = document.getElementById('alertBox');
    el.className = `alert ${isError ? 'alert-error' : 'alert-success'}`;
    el.innerText = msg;
    el.style.display = 'block';
  },
  clearAlert: () => {
    document.getElementById('alertBox').style.display = 'none';
  }
};

async function getPreciseLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      return reject(new Error('Cihazınız konum özelliğini desteklemiyor.'));
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve(pos.coords),
      err => {
        let msg = 'Konum izni alınamadı.';
        if (err.code === 1) msg = 'Konum izni reddedildi. Lütfen tarayıcı ayarlarından izin verin.';
        else if (err.code === 2) msg = 'GPS uydularına erişilemiyor.';
        else if (err.code === 3) msg = 'Konum alma zaman aşımına uğradı.';
        reject(new Error(msg));
      },
      { enableHighAccuracy: true, timeout: 12000, maximumAge: 0 }
    );
  });
}

let currentUser = null;

// Yanlış hesapta kilitlenmeyi önleyen çıkış fonksiyonu
async function handleForceLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (_) {}
  window.location.reload();
}

// Kurtarma / Çıkış butonunu dinle
const btnAbort = document.getElementById('btnAbortSession');
if (btnAbort) {
  btnAbort.addEventListener('click', handleForceLogout);
}

async function checkSession() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;

      // Admin ise ve şu an admin sayfasında değilse yönetim paneline yönlendir
      if (currentUser.role === 'admin' && !window.location.pathname.endsWith('admin.html')) {
        window.location.href = '/admin.html';
        return;
      }

      renderState(data);
    } else {
      showLogin();
    }
  } catch (e) {
    showLogin();
  }
}

function showLogin() {
  document.getElementById('loginSection').style.display = 'block';
  document.getElementById('pairDeviceSection').style.display = 'none';
  document.getElementById('dashboardSection').style.display = 'none';
}

function renderState(data) {
  document.getElementById('loginSection').style.display = 'none';
  
  if (!data.user.has_device) {
    document.getElementById('pairDeviceSection').style.display = 'block';
    document.getElementById('dashboardSection').style.display = 'none';
    return;
  }

  document.getElementById('pairDeviceSection').style.display = 'none';
  document.getElementById('dashboardSection').style.display = 'block';

  document.getElementById('userNameLabel').innerText = `Hoş geldiniz, ${data.user.first_name}`;
  document.getElementById('userSubLabel').innerText = `${data.user.employee_no} • ${data.user.department || 'Genel'}`;

  // Vardiya Rozeti (Artık renderState içinde güvenle çalışır)
  const shiftBadge = document.getElementById('userShiftBadge');
  if (data.today_shift && shiftBadge) {
    shiftBadge.style.display = 'inline-block';
    if (data.today_shift.shift_type === 'OFF') {
      shiftBadge.innerText = 'Bugün Haftalık İzinlisiniz (OFF)';
      shiftBadge.style.background = '#f1f5f9';
      shiftBadge.style.color = '#64748b';
    } else {
      shiftBadge.innerText = `Bugünkü Vardiya: ${data.today_shift.shift_type} (${data.today_shift.start_time || '--:--'} - ${data.today_shift.end_time || '--:--'})`;
      shiftBadge.style.background = '#e0f2fe';
      shiftBadge.style.color = '#0284c7';
    }
  } else if (shiftBadge) {
    shiftBadge.style.display = 'none';
  }

  const att = data.today_attendance;
  const btnIn = document.getElementById('btnCheckIn');
  const btnOut = document.getElementById('btnCheckOut');
  const completed = document.getElementById('completedNotice');

  if (!att) {
    document.getElementById('checkInDisplay').innerText = '--:--';
    document.getElementById('checkOutDisplay').innerText = '--:--';
    btnIn.style.display = 'block';
    btnOut.style.display = 'none';
    completed.style.display = 'none';
  } else {
    document.getElementById('checkInDisplay').innerText = att.check_in_time 
      ? new Date(att.check_in_time).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }) 
      : '--:--';

    document.getElementById('checkOutDisplay').innerText = att.check_out_time 
      ? new Date(att.check_out_time).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }) 
      : '--:--';

    if (att.check_in_time && !att.check_out_time) {
      btnIn.style.display = 'none';
      btnOut.style.display = 'block';
      completed.style.display = 'none';
    } else if (att.check_in_time && att.check_out_time) {
      btnIn.style.display = 'none';
      btnOut.style.display = 'none';
      completed.style.display = 'block';
    }
  }
}

// 1. Giriş Formu (Donanım Parmak İzi ile birlikte gönderilir)
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  UI.clearAlert();
  const employee_no = document.getElementById('empNo').value;
  const password = document.getElementById('password').value;

  try {
    const hwFingerprint = await generateHardwareFingerprint();

    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        employee_no, 
        password,
        device_fingerprint: hwFingerprint
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);

    if (data.user && data.user.role === 'admin') {
      window.location.href = '/admin.html';
      return;
    }

    checkSession();
  } catch (err) {
    UI.alert(err.message);
  }
});

// 2. WebAuthn Cihaz Eşleştirme
document.getElementById('btnPairDevice').addEventListener('click', async () => {
  UI.clearAlert();
  try {
    const optRes = await fetch('/api/webauthn/register-options');
    const options = await optRes.json();
    if (!optRes.ok) throw new Error(options.error);

    const attResp = await startRegistration({ optionsJSON: options });
    const hwFingerprint = await generateHardwareFingerprint();

    const verifyRes = await fetch('/api/webauthn/register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...attResp,
        device_fingerprint: hwFingerprint
      })
    });

    const verifyData = await verifyRes.json();

    if (!verifyRes.ok) {
      if (verifyRes.status === 403) {
        UI.alert(verifyData.error || 'Güvenlik ihlali! Oturum kapatılıyor...', true);
        setTimeout(() => {
          handleForceLogout();
        }, 2500);
        return;
      }
      throw new Error(verifyData.error);
    }

    UI.alert('Cihaz başarıyla eşleştirildi!', false);
    checkSession();
  } catch (err) {
    UI.alert(err.message || 'Cihaz doğrulaması tamamlanamadı.');
  }
});

// 3. İşe Başla / Bitir Akışı
async function executeShiftAction(endpoint) {
  UI.clearAlert();
  try {
    if (!currentUser || !currentUser.has_device) {
      throw new Error('Önce bu cihazı eşleştirmeniz gerekmektedir.');
    }

    UI.alert('Konum alınıyor, lütfen bekleyin...', false);
    const coords = await getPreciseLocation();

    UI.alert('Biyometrik onay bekleniyor...', false);
    const optRes = await fetch('/api/webauthn/assertion-options');
    const options = await optRes.json();
    if (!optRes.ok) throw new Error(options.error);

    const asseResp = await startAuthentication({ optionsJSON: options });
    const hwFingerprint = await generateHardwareFingerprint();

    const actionRes = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assertion: asseResp,
        device_fingerprint: hwFingerprint,
        coords: {
          latitude: coords.latitude,
          longitude: coords.longitude,
          accuracy: coords.accuracy
        }
      })
    });

    const actionData = await actionRes.json();
    if (!actionRes.ok) {
      if (actionRes.status === 403) {
        UI.alert(actionData.error || 'Güvenlik ihlali! Oturum kapatılıyor...', true);
        setTimeout(() => {
          handleForceLogout();
        }, 2500);
        return;
      }
      throw new Error(actionData.error);
    }

    UI.alert(actionData.message, false);
    checkSession();
  } catch (err) {
    UI.alert(err.message);
  }
}

document.getElementById('btnCheckIn').addEventListener('click', () => executeShiftAction('/api/attendance/check-in'));
document.getElementById('btnCheckOut').addEventListener('click', () => executeShiftAction('/api/attendance/check-out'));

document.getElementById('btnLogout').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  location.reload();
});

// Başlat
checkSession();