document.addEventListener('DOMContentLoaded', () => {
    // --- Theming & Settings ---
    const html = document.documentElement;
    const settingsBtn = document.getElementById('btn-settings');
    const closeSettingsBtn = document.getElementById('close-settings');
    const settingsOverlay = document.getElementById('settings-overlay');
    
    // Load saved preferences
    const savedTheme = localStorage.getItem('tempo-theme') || 'linear';
    const savedFont = localStorage.getItem('tempo-font') || 'inter';
    
    setTheme(savedTheme);
    setFont(savedFont);
    
    // Settings Modal Toggles
    settingsBtn.addEventListener('click', () => {
        settingsOverlay.classList.remove('hidden');
    });
    
    closeSettingsBtn.addEventListener('click', () => {
        settingsOverlay.classList.add('hidden');
    });
    
    // Close on background click
    settingsOverlay.addEventListener('click', (e) => {
        if (e.target === settingsOverlay) {
            settingsOverlay.classList.add('hidden');
        }
    });

    // Theme Picker Logic
    document.querySelectorAll('[data-set-theme]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const theme = e.target.getAttribute('data-set-theme');
            setTheme(theme);
        });
    });

    // Font Picker Logic
    document.querySelectorAll('[data-set-font]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const font = e.target.getAttribute('data-set-font');
            setFont(font);
        });
    });

    function setTheme(theme) {
        html.setAttribute('data-theme', theme);
        localStorage.setItem('tempo-theme', theme);
        
        // Update active states
        document.querySelectorAll('[data-set-theme]').forEach(btn => {
            if (btn.getAttribute('data-set-theme') === theme) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    function setFont(font) {
        html.setAttribute('data-font', font);
        localStorage.setItem('tempo-font', font);
        
        // Update active states
        document.querySelectorAll('[data-set-font]').forEach(btn => {
            if (btn.getAttribute('data-set-font') === font) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    // --- Sidebar Toggle ---
    const sidebar = document.getElementById('sidebar');
    const toggleSidebarBtn = document.getElementById('toggle-sidebar');
    let sidebarOpen = true;

    toggleSidebarBtn.addEventListener('click', () => {
        sidebarOpen = !sidebarOpen;
        if (sidebarOpen) {
            sidebar.style.width = 'var(--sidebar-width)';
            sidebar.style.transform = 'translateX(0)';
        } else {
            sidebar.style.width = '0';
            sidebar.style.transform = 'translateX(-100%)';
        }
    });

    // --- Daemon Integration ---
    const daemonInput = document.getElementById('daemon-addr');
    const sessionList = document.getElementById('session-list');
    const omniboxForm = document.getElementById('omnibox-form');
    const urlInput = document.getElementById('url-input');

    function getDaemonAddr() {
        return daemonInput.value.replace(/\/+$/, ""); // strip trailing slashes
    }

    async function fetchSessions() {
        try {
            const res = await fetch(`${getDaemonAddr()}/sessions`);
            if (!res.ok) throw new Error('Failed to fetch');
            const sessions = await res.json();
            
            sessionList.innerHTML = '';
            if (sessions.length === 0) {
                sessionList.innerHTML = '<li class="empty-state">No active sessions</li>';
                return;
            }

            sessions.forEach(session => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 150px;">
                        ${session.url || 'New Tab'}
                    </div>
                    <span class="badge" style="background: ${session.state === 'Adopted' ? '#50fa7b' : 'var(--border-color)'}">
                        ${session.state || 'Idle'}
                    </span>
                `;
                sessionList.appendChild(li);
            });
        } catch (e) {
            sessionList.innerHTML = '<li class="empty-state" style="color: #ff5555">Daemon disconnected</li>';
        }
    }

    omniboxForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        // Try to connect to daemon
        try {
            const res = await fetch(`${getDaemonAddr()}/sessions`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            
            if (res.ok) {
                urlInput.value = '';
                fetchSessions();
            } else {
                console.error("Failed to launch session");
                alert("Failed to start session on the daemon. Is it running?");
            }
        } catch (e) {
            console.error(e);
            alert("Could not reach daemon at " + getDaemonAddr());
        }
    });

    // Poll for sessions every 3 seconds
    setInterval(fetchSessions, 3000);
    fetchSessions();
});
