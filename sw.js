// Service Worker for Objectives notifications

self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Listen for notification clicks
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.openWindow('/'));
});

// Listen for messages from the page to schedule checks
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SCHEDULE') {
    // Store objectives for notification checks
    self.objectives = e.data.objectives;
  }
});

// Check every minute if any notifications are due
self.addEventListener('periodicsync', e => {
  if (e.tag === 'check-notifications') {
    e.waitUntil(checkNotifications());
  }
});

async function checkNotifications() {
  if (!self.objectives) return;
  const now = new Date();
  const hhmm = now.getHours().toString().padStart(2,'0') + ':' + now.getMinutes().toString().padStart(2,'0');
  for (const obj of self.objectives) {
    if (obj.notif && obj.notif_time === hhmm) {
      self.registration.showNotification('Objectives — ' + obj.title, {
        body: obj.desc || 'Time to work on your objective.',
        icon: '/icon.png',
        badge: '/icon.png',
        tag: 'obj-' + obj.id,
        renotify: true
      });
    }
  }
}
