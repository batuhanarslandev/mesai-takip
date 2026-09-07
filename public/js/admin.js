async function loadDashboard() {
  const res = await fetch('/api/admin/dashboard');
  if (!res.ok) return (window.location.href = '/');
  const d = await res.json();
  document.getElementById('statTotal').innerText = d.totalEmployees;
  document.getElementById('statPresent').innerText = d.presentCount;
  document.getElementById('statAbsent').innerText = d.absentCount;
  document.getElementById('statLate').innerText = d.lateCount;
  document.getElementById('statOut').innerText = d.checkedOutCount;
  document.getElementById('statMissingOut').innerText = d.missingCheckouts;
  document.getElementById('statSecurity').innerText = d.securityViolations;
}

async function loadPuantaj(date) {
  const res = await fetch(`/api/admin/puantaj?date=${date}`);
  const data = await res.json();
  const tbody = document.querySelector('#puantajTable tbody');
  tbody.innerHTML = '';

  data.forEach(row => {
    const tr = document.createElement('tr');
    const inTime = row.check_in_time ? new Date(row.check_in_time).toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit' }) : '--:--';
    const outTime = row.check_out_time ? new Date(row.check_out_time).toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit' }) : '--:--';
    
    let badge = '<span class="status-badge badge-danger">Gelmeyen</span>';
    if (row.status === 'normal') badge = '<span class="status-badge badge-success">Zamanında</span>';
    if (row.status === 'late') badge = '<span class="status-badge badge-warning">Geç</span>';
    if (row.status === 'manual_adjusted') badge = '<span class="status-badge badge-warning">Manuel Düzeltme</span>';

    tr.innerHTML = `
      <td><strong>${row.employee_no}</strong></td>
      <td>${row.first_name} ${row.last_name}</td>
      <td>${row.department}</td>
      <td>${inTime}</td>
      <td>${outTime}</td>
      <td>${badge}</td>
      <td><small>${row.verification_mode || '-'}</small></td>
      <td>
        <button class="btn-sm btn-primary" onclick="manualEdit(${row.user_id}, ${row.attendance_id})">Düzelt</button>
        <button class="btn-sm btn-danger" onclick="resetDevice(${row.user_id})">Cihazı Sıfırla</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.manualEdit = async (userId, attId) => {
  const reason = prompt('Manuel kayıt düzeltme gerekçesini giriniz (Zorunlu Denetim Kaydı):');
  if (!reason) return;
  const inTime = prompt('Giriş saati (YYYY-MM-DD HH:mm formatında):');
  const outTime = prompt('Çıkış saati (YYYY-MM-DD HH:mm formatında):');

  const res = await fetch('/api/admin/manual-adjust', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: userId,
      attendance_id: attId,
      work_date: document.getElementById('filterDate').value,
      check_in_time: inTime || null,
      check_out_time: outTime || null,
      reason
    })
  });
  const data = await res.json();
  alert(data.message || data.error);
  loadPuantaj(document.getElementById('filterDate').value);
};

window.resetDevice = async (userId) => {
  const reason = prompt('Personelin cihaz eşleştirmesini kaldırma gerekçesi:');
  if (!reason) return;
  const res = await fetch('/api/admin/reset-device', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId, reason })
  });
  const data = await res.json();
  alert(data.message || data.error);
};

async function loadSettings() {
  const res = await fetch('/api/admin/settings');
  const s = await res.json();
  document.getElementById('setLat').value = s.center_lat;
  document.getElementById('setLon').value = s.center_lon;
  document.getElementById('setRadius').value = s.geofence_radius;
  document.getElementById('setStart').value = s.work_start_time;
  document.getElementById('setTolerance').value = s.late_tolerance_minutes;
  document.getElementById('setMaxAcc').value = s.max_gps_accuracy;
}

document.getElementById('settingsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    center_lat: document.getElementById('setLat').value,
    center_lon: document.getElementById('setLon').value,
    geofence_radius: document.getElementById('setRadius').value,
    work_start_time: document.getElementById('setStart').value,
    late_tolerance_minutes: document.getElementById('setTolerance').value,
    max_gps_accuracy: document.getElementById('setMaxAcc').value
  };
  const res = await fetch('/api/admin/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (res.ok) alert('Ayarlar güncellendi.');
});

// CSV Dışa Aktarma
document.getElementById('btnExportCSV').addEventListener('click', () => {
  const table = document.getElementById('puantajTable');
  let csv = [];
  for (let i = 0; i < table.rows.length; i++) {
    let row = [], cols = table.rows[i].querySelectorAll('td, th');
    for (let j = 0; j < cols.length - 1; j++) {
      row.push('"' + cols[j].innerText.replace(/"/g, '""') + '"');
    }
    csv.push(row.join(';'));
  }
  const blob = new Blob(["\uFEFF" + csv.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Puantaj_${document.getElementById('filterDate').value}.csv`;
  a.click();
});

const todayStr = new Date().toISOString().slice(0, 10);
document.getElementById('filterDate').value = todayStr;
document.getElementById('filterDate').addEventListener('change', (e) => loadPuantaj(e.target.value));

loadDashboard();
loadPuantaj(todayStr);
loadSettings();