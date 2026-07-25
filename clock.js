function updateClock() 
{
  const now = new Date();
  const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); 
  document.getElementById('clock').textContent = timeString;
}
updateClock();
setInterval(updateClock, 1000);