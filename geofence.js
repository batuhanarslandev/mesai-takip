export function calculateHaversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Dünya yarıçapı (metre)
  const phi1 = (lat1 * Math.PI) / 180;
  const phi2 = (lat2 * Math.PI) / 180;
  const deltaPhi = ((lat2 - lat1) * Math.PI) / 180;
  const deltaLambda = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(deltaPhi / 2) * Math.sin(deltaPhi / 2) +
    Math.cos(phi1) * Math.cos(phi2) * Math.sin(deltaLambda / 2) * Math.sin(deltaLambda / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c * 100) / 100; // 2 basamaklı metre hassasiyeti
}

export function evaluateShiftStatus(checkInDate, startTimeStr, toleranceMinutes) {
  const [startHour, startMin] = startTimeStr.split(':').map(Number);
  const targetTime = new Date(checkInDate);
  targetTime.setHours(startHour, startMin, 0, 0);

  const toleranceTime = new Date(targetTime.getTime() + toleranceMinutes * 60000);

  if (checkInDate <= toleranceTime) {
    return 'normal';
  }
  return 'late';
}