<script>
let previousStatuses = {};
let notifCount = 0;

function checkForUpdates() {
    fetch('{{ url_for("student_updates") }}')
    .then(response => response.json())
    .then(data => {
        if(data.success) {
            let notifications = [];

            data.updates.forEach(g => {
                let prevStatus = previousStatuses[g.id];
                if(prevStatus && prevStatus !== g.status) {
                    notifications.push(`Grievance "${g.title}" changed from "${prevStatus}" → "${g.status}"`);

                    // Highlight the row
                    let row = document.getElementById(`grievance-${g.id}`);
                    if(row) {
                        row.style.backgroundColor = '#fff3cd'; // yellow
                        setTimeout(() => { row.style.backgroundColor = ''; }, 5000);

                        // Update the status cell
                        let statusCell = row.querySelector('.status');
                        if(statusCell) statusCell.textContent = g.status;
                    }

                    // Increment badge
                    notifCount += 1;
                    document.getElementById('notif-badge').textContent = notifCount;

                    // Play sound
                    document.getElementById('alert-sound').play();
                }
                previousStatuses[g.id] = g.status;
            });

            if(notifications.length > 0) {
                const notifArea = document.getElementById('notification-area');
                notifArea.innerHTML = notifications.join('<br>');
                notifArea.style.display = 'block';
                setTimeout(() => { notifArea.style.display = 'none'; }, 5000);
            }
        }
    });
}

// Poll every 5 seconds
setInterval(checkForUpdates, 5000);

// Initialize previousStatuses on page load
window.onload = checkForUpdates;
</script>
