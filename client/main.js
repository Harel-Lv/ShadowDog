import { Player } from "./player.js";
import { InputHandler } from "./input.js";
import { BackGround } from "./BackGround.js";
import { FlyingEnemy, ClimbingEnemy , GroundEnemy } from "./enemies/enemies.js";
import { Score } from "./score.js";
import { GameAudio } from "./audio.js";



window.addEventListener('load', () => {
        const canvas = document.getElementById('canvas1');
        const ctx = canvas.getContext('2d');
        canvas.width = 500;
        canvas.height = 500;
        canvas.style.display = 'none';
        let game;
        let lastTime = null;
        let gameStarted = false;
        const restartBtn = document.getElementById('restartBtn');
        const shareScoreBtn = document.getElementById('shareScoreBtn');
        const scoresButton = document.getElementById('scoresButton');
        const adminStatsButton = document.getElementById('adminStatsButton');
        const scoresScreen = document.getElementById('scoresScreen');
        const scoresListEasy = document.getElementById('scoresListEasy');
        const scoresListNormal = document.getElementById('scoresListNormal');
        const scoresListHard = document.getElementById('scoresListHard');
        const adminScreen = document.getElementById('adminScreen');
        const adminOverview = document.getElementById('adminOverview');
        const adminWeeklyTrend = document.getElementById('adminWeeklyTrend');
        const adminActiveHours = document.getElementById('adminActiveHours');
        const adminTrendTitle = document.getElementById('adminTrendTitle');
        const adminTrend7Button = document.getElementById('adminTrend7Button');
        const adminTrend30Button = document.getElementById('adminTrend30Button');
        const adminUserSearch = document.getElementById('adminUserSearch');
        const adminUsersBody = document.getElementById('adminUsersBody');
        const adminBackButton = document.getElementById('adminBackButton');
        const resetStatsButton = document.getElementById('resetStatsButton');
        const backButton = document.getElementById('backButton');
        const resetScoresButton = document.getElementById('resetScoresButton');
        const runtimeConfig = window.SHADOWDOG_CONFIG || {};
        const adminUsername = String(runtimeConfig.adminUsername || window.ADMIN_USERNAME || 'harel').trim().toLowerCase();
        const openSignupButton = document.getElementById('openSignupButton');
        const openLoginButton = document.getElementById('openLoginButton');
        const authUsernameInput = document.getElementById('authUsername');
        const authPasswordInput = document.getElementById('authPassword');
        const authModal = document.getElementById('authModal');
        const authModalTitle = document.getElementById('authModalTitle');
        const authSubmitButton = document.getElementById('authSubmitButton');
        const authCancelButton = document.getElementById('authCancelButton');
        const adminTokenModal = document.getElementById('adminTokenModal');
        const adminTokenModalTitle = document.getElementById('adminTokenModalTitle');
        const adminTokenInput = document.getElementById('adminTokenInput');
        const adminTokenSubmitButton = document.getElementById('adminTokenSubmitButton');
        const adminTokenCancelButton = document.getElementById('adminTokenCancelButton');
        const adminTokenStatus = document.getElementById('adminTokenStatus');
        const logoutButton = document.getElementById('logoutButton');
        const authStatus = document.getElementById('authStatus');
        const authStatusTop = document.getElementById('authStatusTop');
        const audioToggleButton = document.getElementById('audioToggleButton');
        const adminPanelButton = document.getElementById('adminPanelButton');
        const toast = document.getElementById('toast');
        const mainMenu = document.getElementById('mainMenu');
        const preGameScreen = document.getElementById('preGameScreen');
        const touchControls = document.getElementById('touchControls');
        const confirmStart = document.getElementById('confirmStart');
        const cancelStart = document.getElementById('cancelStart');
        const MAX_GAME_TIME = 60000;
        const ENEMY_INTERVAL = 1000;
        const MIN_ENEMY_INTERVAL = 400;
        const BASE_MIN_INTERVAL = MIN_ENEMY_INTERVAL;
        const MAX_MIN_INTERVAL = 800;
        const DIFFICULTY_STEP_MS = 5000;
        const ENEMY_INTERVAL_STEP = 50;
        const SPEED_STEP = 0.2;
        const MAX_SPEED = 8;
        const MAX_ENEMIES = 12;
        const MAX_PARTICLES = 140;
        const DEFAULT_TARGET_DISTANCE = 200;
        const DIFFICULTY_SETTINGS = {
            easy: { targetDistance: 100, enemyMultiplier: 2, minEnemyInterval: 600 },
            normal: { targetDistance: 200, enemyMultiplier: 1, minEnemyInterval: 400 },
            hard: { targetDistance: 250, enemyMultiplier: 2 / 3, minEnemyInterval: 260 }
        };
        let selectedDifficulty = 'normal';
        let playerName = 'Player';
        const AUDIO_MUTED_KEY = 'shadowdog_audio_muted';
        const savedAudioMuted = localStorage.getItem(AUDIO_MUTED_KEY) === '1';
        let authToken = '';
        let currentUser = '';
        let authMode = 'login';
        let adminTokenResolver = null;
        let toastTimer = null;
        let activeGameSessionId = null;
        const TREND_RANGE_STORAGE_KEY = 'shadowdog_admin_trend_days';
        const normalizeTrendDays = (value) => {
            const parsed = Number.parseInt(String(value || ''), 10);
            return parsed === 30 ? 30 : 7;
        };
        let selectedTrendDays = normalizeTrendDays(localStorage.getItem(TREND_RANGE_STORAGE_KEY));
        const audio = new GameAudio({ muted: savedAudioMuted });
        const unlockAndStartBgm = () => {
            audio.ensureStarted();
            audio.startBgm();
        };

        const configuredApiBase = window.API_BASE || runtimeConfig.apiBase || '';
        const localhostFallback = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
            ? 'http://127.0.0.1:3002'
            : 'https://shadowdog-api.onrender.com';
        const API_BASE = String(configuredApiBase || localhostFallback).replace(/\/+$/, '');
        const apiUrl = (path) => `${API_BASE}${path}`;
        const isTouchDevice = window.matchMedia('(pointer: coarse)').matches ||
            'ontouchstart' in window ||
            (navigator.maxTouchPoints || 0) > 0;

        if (isTouchDevice) {
            document.body.classList.add('touch-device');
        }

        function updateTouchControlsVisibility() {
            const active = isTouchDevice && gameStarted && canvas.style.display === 'block';
            document.body.classList.toggle('game-active', active);
            if (touchControls) {
                touchControls.setAttribute('aria-hidden', active ? 'false' : 'true');
            }
        }

        function showToast(message, type = 'error') {
            if (!toast) return;
            toast.textContent = message;
            toast.className = `toast toast--${type}`;
            toast.style.display = 'block';
            if (toastTimer) clearTimeout(toastTimer);
            toastTimer = setTimeout(() => {
                toast.style.display = 'none';
            }, 2600);
        }

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function getPublicGameUrl() {
            const configured = String(runtimeConfig.publicGameUrl || runtimeConfig.publicUrl || '').trim();
            if (configured) return configured.replace(/\/+$/, '');
            return `${window.location.origin}${window.location.pathname}`;
        }

        async function copyToClipboard(text) {
            if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') return false;
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch {
                return false;
            }
        }

        function buildShareText(gameInstance) {
            const didWin = gameInstance.distance >= gameInstance.targetDistance;
            const verdict = didWin ? 'I won' : 'I scored';
            const difficulty = String(gameInstance.difficulty || 'normal').toUpperCase();
            const score = Number(gameInstance.score || 0);
            return `${verdict} ${score} points on ${difficulty} in Shadow Dog. Can you beat me?`;
        }

        async function shareGameScore(gameInstance) {
            if (!gameInstance) return;
            const text = buildShareText(gameInstance);
            const url = getPublicGameUrl();
            const combined = `${text} ${url}`.trim();

            if (navigator.share) {
                try {
                    await navigator.share({
                        title: 'Shadow Dog Challenge',
                        text,
                        url
                    });
                    showToast('Score shared successfully.', 'success');
                    return;
                } catch (err) {
                    if (String(err?.name || '') === 'AbortError') return;
                }
            }

            window.open(`https://wa.me/?text=${encodeURIComponent(combined)}`, '_blank', 'noopener');
            const copied = await copyToClipboard(combined);
            showToast(copied ? 'Share text copied and WhatsApp opened.' : 'WhatsApp share opened.', 'success');
        }

        function setAuthState(token, username) {
            authToken = token || '';
            currentUser = username || '';
            if (currentUser) {
                authStatus.textContent = `Logged in as ${currentUser}`;
                authStatusTop.textContent = currentUser;
                openSignupButton.style.display = 'none';
                openLoginButton.style.display = 'none';
                logoutButton.style.display = 'inline-block';
            } else {
                authStatus.textContent = 'Guest mode (scores will not be saved)';
                authStatusTop.textContent = 'Guest';
                openSignupButton.style.display = 'inline-block';
                openLoginButton.style.display = 'inline-block';
                logoutButton.style.display = 'none';
            }
            updateAdminToolsVisibility();
        }

        function updateAudioToggleLabel() {
            if (!audioToggleButton) return;
            audioToggleButton.textContent = audio.muted ? 'Sound: Off' : 'Sound: On';
        }

        function userCanSeeAdminReset() {
            const loggedInAdmin = Boolean(currentUser) && currentUser.trim().toLowerCase() === adminUsername;
            return loggedInAdmin;
        }

        function updateAdminToolsVisibility() {
            if (!resetScoresButton) return;
            const visible = userCanSeeAdminReset();
            resetScoresButton.style.display = visible ? 'inline-block' : 'none';
            if (resetStatsButton) resetStatsButton.style.display = visible ? 'inline-block' : 'none';
            if (adminPanelButton) adminPanelButton.style.display = visible ? 'inline-block' : 'none';
            if (adminStatsButton) adminStatsButton.style.display = visible ? 'inline-block' : 'none';
        }

        function openAuthModal(mode) {
            authMode = mode;
            authModalTitle.textContent = mode === 'signup' ? 'Sign Up' : 'Login';
            authSubmitButton.textContent = mode === 'signup' ? 'Create Account' : 'Login';
            authStatus.textContent = 'Enter username and password';
            authPasswordInput.value = '';
            authModal.style.display = 'flex';
            authUsernameInput.focus();
        }

        function closeAuthModal() {
            authModal.style.display = 'none';
        }

        function closeAdminTokenModal() {
            if (adminTokenModal) adminTokenModal.style.display = 'none';
        }

        function resolveAdminToken(value) {
            const resolver = adminTokenResolver;
            adminTokenResolver = null;
            closeAdminTokenModal();
            if (resolver) resolver(value);
        }

        function requestAdminToken(actionLabel) {
            if (!adminTokenModal || !adminTokenInput) {
                return Promise.resolve(window.prompt(`Admin token required to ${actionLabel}:`)?.trim() || '');
            }
            if (adminTokenResolver) return Promise.resolve('');
            return new Promise((resolve) => {
                adminTokenResolver = resolve;
                if (adminTokenModalTitle) adminTokenModalTitle.textContent = 'Admin Verification';
                if (adminTokenStatus) adminTokenStatus.textContent = `Enter admin token to ${actionLabel}`;
                adminTokenInput.value = '';
                adminTokenModal.style.display = 'flex';
                adminTokenInput.focus();
            });
        }

        async function apiFetch(path, options = {}) {
            const opts = { ...options };
            const headers = { ...(opts.headers || {}) };
            if (authToken && !headers.Authorization) {
                headers.Authorization = `Bearer ${authToken}`;
            }
            opts.headers = headers;
            if (!opts.credentials) {
                opts.credentials = 'include';
            }
            return fetch(apiUrl(path), opts);
        }

        async function authRequest(path, payload) {
            let res;
            try {
                res = await apiFetch(path, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
            } catch {
                throw new Error('Network error: cannot reach server');
            }
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(data.error || 'Authentication failed');
            }
            return data;
        }

        async function hydrateAuthFromServer() {
            try {
                const res = await apiFetch('/auth/me');
                if (!res.ok) {
                    setAuthState('', '');
                    return '';
                }
                const data = await res.json().catch(() => ({}));
                const username = data?.user?.username || '';
                setAuthState('', username);
                return username;
            } catch {
                setAuthState('', '');
                return '';
            }
        }

        async function startGameSessionTracking() {
            activeGameSessionId = null;
            if (!currentUser) return;
            try {
                const res = await apiFetch('/analytics/session/start', {
                    method: 'POST',
                });
                const data = await res.json().catch(() => ({}));
                const serverSessionId = data?.sessionId ?? data?.id;
                if (res.ok && Number.isFinite(Number(serverSessionId))) {
                    activeGameSessionId = Number(serverSessionId);
                }
            } catch {
                // Ignore analytics start failures
            }
        }

        async function endGameSessionTracking(gameInstance, didWin) {
            const sessionId = activeGameSessionId;
            activeGameSessionId = null;
            if (!sessionId || !currentUser || !gameInstance) return;
            const durationMs = Math.max(0, Math.round(gameInstance.time || 0));
            const payload = {
                sessionId,
                durationMs,
                didWin: Boolean(didWin),
                score: Number(gameInstance.score || 0),
                difficulty: String(gameInstance.difficulty || 'normal')
            };
            try {
                await apiFetch('/analytics/session/end', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload)
                });
            } catch {
                // Ignore analytics end failures
            }
        }

        function formatDuration(ms) {
            const totalSeconds = Math.max(0, Math.floor((ms || 0) / 1000));
            const hours = Math.floor(totalSeconds / 3600);
            const minutes = Math.floor((totalSeconds % 3600) / 60);
            const seconds = totalSeconds % 60;
            if (hours > 0) return `${hours}h ${minutes}m`;
            if (minutes > 0) return `${minutes}m ${seconds}s`;
            return `${seconds}s`;
        }

        function formatPercent(numerator, denominator) {
            const num = Number(numerator || 0);
            const den = Number(denominator || 0);
            if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0) return '0%';
            return `${((num / den) * 100).toFixed(1)}%`;
        }

        function getClientTimezoneOffsetMinutes() {
            const offset = new Date().getTimezoneOffset();
            if (!Number.isInteger(offset)) return 0;
            return Math.max(-840, Math.min(840, offset));
        }

        function formatShortDay(dateLike) {
            const date = new Date(dateLike);
            if (Number.isNaN(date.getTime())) return String(dateLike || '');
            return date.toLocaleDateString(undefined, { weekday: 'short' });
        }

        function updateTrendRangeUI() {
            if (adminTrend7Button) {
                adminTrend7Button.classList.toggle('is-active', selectedTrendDays === 7);
            }
            if (adminTrend30Button) {
                adminTrend30Button.classList.toggle('is-active', selectedTrendDays === 30);
            }
            if (adminTrendTitle) {
                adminTrendTitle.textContent = `Player Trend (${selectedTrendDays} Days)`;
            }
        }

        function renderWeeklyTrendChart(container, rows) {
            if (!container) return;
            const rawRows = Array.isArray(rows) ? rows : [];
            const normalized = rawRows
                .map((row) => {
                    const date = new Date(row?.day);
                    const users = Math.max(0, Number(row?.users || 0));
                    if (Number.isNaN(date.getTime())) return null;
                    return { day: date, users };
                })
                .filter(Boolean)
                .sort((a, b) => a.day.getTime() - b.day.getTime())
                .slice(-Math.max(1, normalizeTrendDays(selectedTrendDays)));

            if (normalized.length === 0) {
                container.innerHTML = '';
                const emptyState = document.createElement('div');
                emptyState.className = 'adminTrendLabel';
                emptyState.textContent = 'No weekly data yet';
                container.appendChild(emptyState);
                return;
            }

            const niceAxisMax = (value) => {
                if (!Number.isFinite(value) || value <= 1) return 1;
                const exponent = Math.floor(Math.log10(value));
                const fraction = value / (10 ** exponent);
                let niceFraction = 1;
                if (fraction <= 1) niceFraction = 1;
                else if (fraction <= 2) niceFraction = 2;
                else if (fraction <= 5) niceFraction = 5;
                else niceFraction = 10;
                return niceFraction * (10 ** exponent);
            };

            const width = 920;
            const height = 220;
            const padLeft = 54;
            const padRight = 18;
            const padTop = 20;
            const padBottom = 36;
            const plotW = width - padLeft - padRight;
            const plotH = height - padTop - padBottom;
            const maxUsersRaw = Math.max(1, ...normalized.map((d) => d.users));
            const axisMax = niceAxisMax(maxUsersRaw);
            const yTicks = 4;
            const yTickStep = axisMax / yTicks;

            const points = normalized.map((d, i) => {
                const ratioX = normalized.length === 1 ? 0 : i / (normalized.length - 1);
                const x = padLeft + ratioX * plotW;
                const y = padTop + (1 - (d.users / axisMax)) * plotH;
                const dayLabel = d.day.toLocaleDateString(undefined, { weekday: 'short' });
                const dateLabel = d.day.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' });
                return {
                    x,
                    y,
                    users: d.users,
                    dayLabel,
                    xLabel: `${dayLabel} ${dateLabel}`,
                    titleLabel: d.day.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })
                };
            });

            const linePath = points
                .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`)
                .join(' ');
            const areaPath = `${linePath} L ${(padLeft + plotW).toFixed(2)} ${(padTop + plotH).toFixed(2)} L ${padLeft.toFixed(2)} ${(padTop + plotH).toFixed(2)} Z`;

            const yGridSvg = Array.from({ length: yTicks + 1 }, (_, i) => {
                const value = yTickStep * (yTicks - i);
                const y = padTop + (i / yTicks) * plotH;
                return `
                    <line class="adminTrendGrid" x1="${padLeft}" y1="${y.toFixed(2)}" x2="${(padLeft + plotW).toFixed(2)}" y2="${y.toFixed(2)}"></line>
                    <text class="adminTrendYLabel" x="${(padLeft - 8).toFixed(2)}" y="${(y + 4).toFixed(2)}" text-anchor="end">${Math.round(value)}</text>
                `;
            }).join('');

            const pointsSvg = points
                .map((p) => `
                    <circle class="adminTrendDot" cx="${p.x.toFixed(2)}" cy="${p.y.toFixed(2)}" r="4">
                        <title>${escapeHtml(p.titleLabel)}: ${Math.round(p.users)} players</title>
                    </circle>
                `)
                .join('');

            const labelStep = points.length <= 10 ? 1 : Math.ceil(points.length / 8);
            const xLabelsSvg = points
                .map((p, i) => {
                    const isLast = i === points.length - 1;
                    if (!isLast && i % labelStep !== 0) return '';
                    return `<text class="adminTrendXLabel" x="${p.x.toFixed(2)}" y="${(height - 10).toFixed(2)}" text-anchor="middle">${escapeHtml(p.xLabel)}</text>`;
                })
                .join('');

            const peak = points.reduce((best, p) => (p.users > best.users ? p : best), points[0]);
            const last = points[points.length - 1];

            container.innerHTML = `
                <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Weekly connected players trend">
                    ${yGridSvg}
                    <line class="adminTrendAxis" x1="${padLeft}" y1="${(padTop + plotH).toFixed(2)}" x2="${(padLeft + plotW).toFixed(2)}" y2="${(padTop + plotH).toFixed(2)}"></line>
                    <line class="adminTrendAxis" x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${(padTop + plotH).toFixed(2)}"></line>
                    <path class="adminTrendArea" d="${areaPath}"></path>
                    <path class="adminTrendPath" d="${linePath}"></path>
                    ${pointsSvg}
                    ${xLabelsSvg}
                </svg>
                <div class="adminTrendMeta">
                    <span class="adminTrendStat"><strong>Peak:</strong> ${Math.round(peak.users)} (${escapeHtml(peak.titleLabel)})</span>
                    <span class="adminTrendStat"><strong>Latest:</strong> ${Math.round(last.users)} (${escapeHtml(last.titleLabel)})</span>
                </div>
            `;
        }

        function renderActiveHoursHeatmap(container, rows) {
            if (!container) return;
            const map = new Map();
            if (Array.isArray(rows)) {
                rows.forEach((row) => {
                    const hour = Number.parseInt(String(row?.hour ?? ''), 10);
                    if (!Number.isInteger(hour) || hour < 0 || hour > 23) return;
                    map.set(hour, {
                        sessions: Math.max(0, Number(row?.sessions || 0)),
                        users: Math.max(0, Number(row?.users || 0))
                    });
                });
            }
            const hours = Array.from({ length: 24 }, (_, hour) => {
                const item = map.get(hour) || { sessions: 0, users: 0 };
                return { hour, sessions: item.sessions, users: item.users };
            });
            const maxSessions = Math.max(1, ...hours.map((h) => h.sessions));
            container.innerHTML = '';
            hours.forEach((item) => {
                const intensity = item.sessions / maxSessions;
                const alpha = 0.08 + intensity * 0.62;
                const borderAlpha = 0.15 + intensity * 0.35;
                const cell = document.createElement('div');
                cell.className = 'adminHeatmapCell';
                cell.style.background = `rgba(0, 255, 204, ${alpha.toFixed(3)})`;
                cell.style.borderColor = `rgba(0, 255, 204, ${borderAlpha.toFixed(3)})`;
                cell.title = `${String(item.hour).padStart(2, '0')}:00 - Sessions: ${Math.round(item.sessions)}, Users: ${Math.round(item.users)}`;
                cell.innerHTML = `
                    <span class="adminHeatmapHour">${String(item.hour).padStart(2, '0')}:00</span>
                    <span class="adminHeatmapValue">${Math.round(item.sessions)}</span>
                `;
                container.appendChild(cell);
            });
        }

        async function adminFetch(path) {
            if (!currentUser) throw new Error('Login as admin first');
            const res = await apiFetch(path);
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                const message = data.error || `Failed admin request (${res.status})`;
                throw new Error(message);
            }
            return data;
        }

        async function fetchTrafficTrend(days) {
            const normalizedDays = normalizeTrendDays(days);
            const tzOffset = getClientTimezoneOffsetMinutes();
            try {
                const traffic = await adminFetch(`/admin/traffic?days=${normalizedDays}&tz_offset_min=${tzOffset}`);
                return Array.isArray(traffic) ? traffic : [];
            } catch (err) {
                const message = String(err?.message || '');
                if (!message.includes('(404)')) throw err;
                if (normalizedDays === 7) {
                    const fallback = await adminFetch(`/admin/traffic-week?tz_offset_min=${tzOffset}`).catch(() => []);
                    return Array.isArray(fallback) ? fallback : [];
                }
                throw new Error('30-day trend is not supported by the current server deployment. Redeploy API to latest version.');
            }
        }

        async function openAdminPanel() {
            if (!userCanSeeAdminReset()) return;
            updateTrendRangeUI();
            const renderUsersStatusRow = (message) => {
                if (!adminUsersBody) return;
                adminUsersBody.innerHTML = `<tr class="adminTableStatusRow"><td colspan="9">${escapeHtml(message)}</td></tr>`;
            };
            if (adminUserSearch) adminUserSearch.value = '';
            renderUsersStatusRow('Loading players...');
            try {
                let overview;
                let users;
                let trendTraffic = [];
                let activeHours = [];
                try {
                    const tzOffset = getClientTimezoneOffsetMinutes();
                    const [dashboard, traffic, hourly] = await Promise.all([
                        adminFetch('/admin/dashboard?limit=200'),
                        fetchTrafficTrend(selectedTrendDays),
                        adminFetch(`/admin/active-hours?tz_offset_min=${tzOffset}`).catch(() => [])
                    ]);
                    overview = dashboard?.overview || {};
                    users = Array.isArray(dashboard?.users) ? dashboard.users : [];
                    trendTraffic = Array.isArray(traffic) ? traffic : [];
                    activeHours = Array.isArray(hourly) ? hourly : [];
                } catch (err) {
                    const message = String(err?.message || '');
                    if (!message.includes('(404)')) throw err;
                    const [fallbackOverview, fallbackUsers] = await Promise.all([
                        adminFetch('/admin/overview'),
                        adminFetch('/admin/users?limit=200')
                    ]);
                    overview = fallbackOverview || {};
                    users = Array.isArray(fallbackUsers) ? fallbackUsers : [];
                    trendTraffic = await fetchTrafficTrend(selectedTrendDays);
                    activeHours = await adminFetch(`/admin/active-hours?tz_offset_min=${getClientTimezoneOffsetMinutes()}`).catch(() => []);
                }
                const totalPlay = formatDuration(Number(overview.total_play_time_ms || 0));
                const totalGames = Number(overview.total_games || 0);
                const totalWins = Number(overview.total_wins || 0);
                adminOverview.innerHTML = `
                    <div><strong>Total users:</strong> ${escapeHtml(overview.total_users ?? 0)}</div>
                    <div><strong>Total games:</strong> ${escapeHtml(totalGames)}</div>
                    <div><strong>Total play time:</strong> ${escapeHtml(totalPlay)}</div>
                    <div><strong>Total wins:</strong> ${escapeHtml(totalWins)}</div>
                    <div><strong>Win rate:</strong> ${escapeHtml(formatPercent(totalWins, totalGames))}</div>
                `;
                renderWeeklyTrendChart(adminWeeklyTrend, trendTraffic);
                renderActiveHoursHeatmap(adminActiveHours, activeHours);
                const sortedUsers = users
                    .slice()
                    .sort((a, b) => String(a?.username || '').localeCompare(String(b?.username || ''), undefined, { sensitivity: 'base' }));
                const renderAdminUsersRows = () => {
                    const query = String(adminUserSearch?.value || '').trim().toLowerCase();
                    const visibleUsers = query
                        ? sortedUsers.filter((u) => String(u?.username || '').toLowerCase().includes(query))
                        : sortedUsers;
                    adminUsersBody.innerHTML = '';
                    if (visibleUsers.length === 0) {
                        renderUsersStatusRow('No matching users');
                        return;
                    }
                    visibleUsers.forEach((u) => {
                        const tr = document.createElement('tr');
                        const registered = u.created_at ? new Date(u.created_at).toLocaleString() : '-';
                        const lastPlayed = u.last_played_at ? new Date(u.last_played_at).toLocaleString() : '-';
                        const userId = Number(u.id || 0);
                        const gamesPlayed = Number(u.games_played || 0);
                        const gamesWon = Number(u.games_won || 0);
                        const canDelete = Number.isInteger(userId) && userId > 0 && String(u.username || '').trim().toLowerCase() !== adminUsername;
                        tr.innerHTML = `
                            <td>${escapeHtml(u.username || '-')}</td>
                            <td>${escapeHtml(registered)}</td>
                            <td>${escapeHtml(formatDuration(Number(u.total_play_time_ms || 0)))}</td>
                            <td>${escapeHtml(gamesPlayed)}</td>
                            <td>${escapeHtml(gamesWon)}</td>
                            <td>${escapeHtml(formatPercent(gamesWon, gamesPlayed))}</td>
                            <td>${escapeHtml(u.best_score ?? 0)}</td>
                            <td>${escapeHtml(lastPlayed)}</td>
                            <td>${canDelete ? `<button type="button" class="adminDeleteBtn" data-user-id="${userId}" data-username="${escapeHtml(String(u.username || ''))}">Delete</button>` : '-'}</td>
                        `;
                        adminUsersBody.appendChild(tr);
                    });
                    adminUsersBody.querySelectorAll('.adminDeleteBtn').forEach((btn) => {
                        btn.addEventListener('click', async () => {
                            const userId = Number(btn.getAttribute('data-user-id') || 0);
                            const username = String(btn.getAttribute('data-username') || '');
                            if (!Number.isInteger(userId) || userId <= 0) return;
                            if (!window.confirm(`Delete player "${username}" completely? This also removes their high scores and statistics.`)) {
                                return;
                            }
                            const adminToken = await requestAdminToken('delete this player');
                            if (!adminToken) return;
                            const headers = { 'x-admin-token': adminToken.trim() };
                            const res = await apiFetch(`/admin/users/${userId}`, {
                                method: 'DELETE',
                                headers
                            }).catch(() => null);
                            if (!res) {
                                showToast('Network error while deleting player.', 'error');
                                return;
                            }
                            const payload = await res.json().catch(() => ({}));
                            if (res.status === 401) {
                                showToast('Login as admin is required.', 'error');
                                return;
                            }
                            if (res.status === 403) {
                                showToast('Forbidden: admin token or account is invalid.', 'error');
                                return;
                            }
                            if (res.status === 404) {
                                showToast('Player was not found.', 'error');
                                return;
                            }
                            if (!res.ok) {
                                showToast(payload.error || 'Failed to delete player.', 'error');
                                return;
                            }
                            showToast(`Player "${username}" deleted.`, 'success');
                            openAdminPanel();
                        });
                    });
                };
                renderAdminUsersRows();
                if (adminUserSearch) {
                    adminUserSearch.oninput = () => {
                        renderAdminUsersRows();
                    };
                }
                mainMenu.style.display = 'none';
                scoresScreen.style.display = 'none';
                if (adminScreen) adminScreen.style.display = 'flex';
                updateTouchControlsVisibility();
            } catch (err) {
                renderUsersStatusRow(`Failed to load players: ${String(err?.message || 'Unknown error')}`);
                mainMenu.style.display = 'none';
                scoresScreen.style.display = 'none';
                if (adminScreen) adminScreen.style.display = 'flex';
                updateTouchControlsVisibility();
                showToast(err.message || 'Failed to open admin panel', 'error');
            }
        }

        async function saveScore(game) {
            if (!currentUser) return false;
            const entry = {
                score: game.score,
                difficulty: game.difficulty
            };
            try {
                const res = await apiFetch('/scores', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(entry)
                });
                return res.ok;
            } catch {
                // Ignore network errors for now
                return false;
            }
        }

        async function renderScores() {
            const difficultyKeys = ['easy', 'normal', 'hard'];
            const byDifficulty = { easy: [], normal: [], hard: [] };
            const responses = await Promise.all(difficultyKeys.map(async (difficulty) => {
                try {
                    const res = await fetch(apiUrl(`/scores?difficulty=${difficulty}&limit=5`));
                    if (!res.ok) return { difficulty, data: [] };
                    const data = await res.json();
                    return { difficulty, data: Array.isArray(data) ? data : [] };
                } catch {
                    return { difficulty, data: [] };
                }
            }));
            responses.forEach(({ difficulty, data }) => {
                byDifficulty[difficulty] = data;
            });
            const lists = [
                { list: scoresListEasy, data: byDifficulty.easy },
                { list: scoresListNormal, data: byDifficulty.normal },
                { list: scoresListHard, data: byDifficulty.hard }
            ];
            lists.forEach(({ list, data }) => {
                list.innerHTML = '';
                if (data.length === 0) {
                    const li = document.createElement('li');
                    li.textContent = 'No scores yet';
                    list.appendChild(li);
                    return;
                }
                data.slice(0, 5).forEach((score) => {
                    const li = document.createElement('li');
                    const name = score.name || 'Player';
                    const when = score.created_at ? ` (${new Date(score.created_at).toLocaleDateString()})` : '';
                    li.textContent = `${name} - SCORE: ${score.score ?? 0}${when}`;
                    list.appendChild(li);
                });
            });
        }

        function loadPlayerSettings() {
            const savedDifficulty = localStorage.getItem('shadowdog_difficulty');
            if (savedDifficulty && DIFFICULTY_SETTINGS[savedDifficulty]) {
                selectedDifficulty = savedDifficulty;
                const radio = preGameScreen.querySelector(`input[name="difficulty"][value="${savedDifficulty}"]`);
                if (radio) radio.checked = true;
            }
        }

        function applyDifficultySettings(gameInstance) {
            const settings = DIFFICULTY_SETTINGS[selectedDifficulty] || DIFFICULTY_SETTINGS.normal;
            gameInstance.targetDistance = settings.targetDistance || DEFAULT_TARGET_DISTANCE;
            gameInstance.enemyInterval = ENEMY_INTERVAL * settings.enemyMultiplier;
            gameInstance.minEnemyInterval = Math.min(
                MAX_MIN_INTERVAL,
                Math.max(150, settings.minEnemyInterval || BASE_MIN_INTERVAL)
            );
            gameInstance.playerName = playerName;
            gameInstance.difficulty = selectedDifficulty;
        }





        class Game {
            constructor(width, height) {
                this.width = width;
                this.height = height;
                this.groundMargin = 50;
                this.speed = 0;
                this.maxSpeed = 4; // Maximum speed for horizontal movement
                this.background = new BackGround(this);
                this.player = new Player(this);
                this.input = new InputHandler(this);
                this.Score = new Score(this); // Initialize score
                this.collision = []; // Initialize collision detection
                this.enemies = [];
                this.particles = [];
                this.maxEnemies = MAX_ENEMIES;
                this.maxParticles = MAX_PARTICLES;
                this.enemyTimer = 0; // Timer for enemy spawning
                this.enemyInterval = ENEMY_INTERVAL; // Interval for enemy spawning in milliseconds
                this.minEnemyInterval = MIN_ENEMY_INTERVAL;
                this.debug = true; // Debug mode
                this.score = 0; // Game score
                this.time = 0; // Game time
                this.difficultyTimer = 0;
                this.distance = 0;
                this.targetDistance = DEFAULT_TARGET_DISTANCE;
                this.maxtime = MAX_GAME_TIME; // Maximum game time in milliseconds
                this.gameOver = false; // Game over flag
                this.scoreSaved = false;
                this.scoreSaveAttempted = false;
                this.frontColor = 'black'; // Color for the score text
                this.lives = 5; // Player lives
                this.paused = false; 
                this.hitFreezeTimer = 0;
                this.invulnTimer = 0;
                this.endSoundPlayed = false;
                this.analyticsSent = false;
                this.audio = audio;
                this.frameScale = 1;
            }

            update(deltaTime) {
                this.frameScale = Math.max(0, Math.min(3, deltaTime / 16.6667));
                this.time += deltaTime; // Increment game time
                this.difficultyTimer += deltaTime;
                this.distance += (this.speed * deltaTime) / 1000;
                if (this.hitFreezeTimer > 0) {
                    this.hitFreezeTimer = Math.max(0, this.hitFreezeTimer - deltaTime);
                }
                if (this.invulnTimer > 0) {
                    this.invulnTimer = Math.max(0, this.invulnTimer - deltaTime);
                }
                if (this.time > this.maxtime) {
                    this.gameOver = true; // Set game over flag if time exceeds maximum
                }
                if (this.distance >= this.targetDistance) {
                    this.gameOver = true;
                }
                if (this.difficultyTimer >= DIFFICULTY_STEP_MS) {
                    this.difficultyTimer = 0;
                    this.enemyInterval = Math.max(this.minEnemyInterval, this.enemyInterval - ENEMY_INTERVAL_STEP);
                    this.maxSpeed = Math.min(MAX_SPEED, this.maxSpeed + SPEED_STEP);
                }
                this.background.update();
                this.player.update(this.input.keys, deltaTime);
                // Update enemies
                if (this.enemyTimer > this.enemyInterval) {
                    this.addEnemy();
                    this.enemyTimer = 0; // Reset timer after adding an enemy
                }
                else this.enemyTimer += deltaTime; // Increment timer by deltaTime

                for (let i = this.enemies.length - 1; i >= 0; i--) {
                    const enemy = this.enemies[i];
                    enemy.update(deltaTime);
                    if (enemy.markForDeletion) this.enemies.splice(i, 1);
                }

                for (let i = this.particles.length - 1; i >= 0; i--) {
                    const particle = this.particles[i];
                    particle.update(deltaTime);
                    if (particle.markForDeletion) this.particles.splice(i, 1);
                }

                for (let i = this.collision.length - 1; i >= 0; i--) {
                    const collision = this.collision[i];
                    collision.update(deltaTime);
                    if (collision.markForDeletion) this.collision.splice(i, 1);
                }

                if (this.particles.length > this.maxParticles) {
                    this.particles.splice(0, this.particles.length - this.maxParticles);
                }
            }
            draw(context) {
                this.background.draw(context);
                this.player.draw(context);
                this.enemies.forEach(enemy => {
                    enemy.draw(context);
                });
                this.Score.draw(context);

                this.particles.forEach(particle => {
                    particle.draw(context);
                });
                this.collision.forEach(collision => {
                    collision.draw(context);
                });
            }
            addEnemy() {
                if (this.speed <= 0 || this.enemies.length >= this.maxEnemies) return;

                const roll = Math.random();
                if (roll < 0.45) {
                    this.enemies.push(new GroundEnemy(this));
                } else if (roll < 0.8) {
                    this.enemies.push(new ClimbingEnemy(this));
                } else {
                    this.enemies.push(new FlyingEnemy(this));
                }

                if (
                    this.difficulty === 'hard' &&
                    this.enemies.length < this.maxEnemies &&
                    Math.random() < 0.2
                ) {
                    this.enemies.push(new FlyingEnemy(this));
                }
            }
    
        }
  

        function animate(timeStamp) {
            if (!gameStarted || !game) return;
            if (lastTime === null) lastTime = timeStamp;
            const deltaTime = Math.min(50, timeStamp - lastTime);
            lastTime = timeStamp; // Convert to seconds
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            if(!game.paused) {
                game.update(deltaTime);
            }
            if (game.gameOver) {
                if (!game.analyticsSent) {
                    game.analyticsSent = true;
                    endGameSessionTracking(game, game.distance >= game.targetDistance);
                }
                if (!game.endSoundPlayed) {
                    game.endSoundPlayed = true;
                    audio.onGameEnd(game.distance >= game.targetDistance);
                }
                if (!game.scoreSaveAttempted && game.distance >= game.targetDistance) {
                    game.scoreSaveAttempted = true;
                    saveScore(game).then((saved) => {
                        game.scoreSaved = saved;
                        if (!saved) {
                            showToast('Score was not saved. Please log in and try again.', 'error');
                        }
                    });
                }
                restartBtn.style.display = 'block'; // Show restart button on game over
                if (shareScoreBtn) shareScoreBtn.style.display = 'block';
            }

            game.draw(ctx);
            
            if (!game.gameOver) requestAnimationFrame(animate);
        }

         restartBtn.addEventListener('click', () => {
             location.reload(); // Reload the game on button click
         });

        if (shareScoreBtn) {
            shareScoreBtn.addEventListener('click', async () => {
                await shareGameScore(game);
            });
        }

        setAuthState('', '');
        hydrateAuthFromServer();
        updateAudioToggleLabel();
        unlockAndStartBgm();
        window.addEventListener('pointerdown', unlockAndStartBgm, { once: true, passive: true });
        window.addEventListener('keydown', unlockAndStartBgm, { once: true });

        if (audioToggleButton) {
            audioToggleButton.addEventListener('click', () => {
                audio.ensureStarted();
                const muted = audio.toggleMuted();
                localStorage.setItem(AUDIO_MUTED_KEY, muted ? '1' : '0');
                updateAudioToggleLabel();
            });
        }

        openSignupButton.addEventListener('click', () => openAuthModal('signup'));
        openLoginButton.addEventListener('click', () => openAuthModal('login'));
        authCancelButton.addEventListener('click', closeAuthModal);
        authModal.addEventListener('click', (event) => {
            if (event.target === authModal) closeAuthModal();
        });
        if (adminTokenCancelButton) {
            adminTokenCancelButton.addEventListener('click', () => resolveAdminToken(''));
        }
        if (adminTokenSubmitButton) {
            adminTokenSubmitButton.addEventListener('click', () => {
                const token = (adminTokenInput?.value || '').trim();
                if (!token) {
                    if (adminTokenStatus) adminTokenStatus.textContent = 'Admin token is required';
                    return;
                }
                resolveAdminToken(token);
            });
        }
        if (adminTokenInput) {
            adminTokenInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    const token = (adminTokenInput.value || '').trim();
                    if (!token) {
                        if (adminTokenStatus) adminTokenStatus.textContent = 'Admin token is required';
                        return;
                    }
                    resolveAdminToken(token);
                }
            });
        }
        if (adminTokenModal) {
            adminTokenModal.addEventListener('click', (event) => {
                if (event.target === adminTokenModal) resolveAdminToken('');
            });
        }
        authSubmitButton.addEventListener('click', async () => {
            const username = authUsernameInput.value.trim();
            const password = authPasswordInput.value;
            if (!username) {
                authStatus.textContent = 'Username is required';
                return;
            }
            if (authMode === 'signup' && username.length < 3) {
                authStatus.textContent = 'Username must be at least 3 characters';
                return;
            }
            if (authMode === 'signup' && username.length > 16) {
                authStatus.textContent = 'Username must be at most 16 characters';
                return;
            }
            if (authMode === 'signup' && !/^[A-Za-z0-9_]+$/.test(username)) {
                authStatus.textContent = 'Username can contain only letters, numbers, and underscore';
                return;
            }
            if (!password) {
                authStatus.textContent = 'Password is required';
                return;
            }
            if (authMode === 'signup' && password.length < 6) {
                authStatus.textContent = 'Password must be at least 6 characters';
                return;
            }
            try {
                const path = authMode === 'signup' ? '/auth/signup' : '/auth/login';
                await authRequest(path, { username, password });
                const hydratedUser = await hydrateAuthFromServer();
                if (!hydratedUser) {
                    throw new Error('Login failed: browser blocked session cookie');
                }
                closeAuthModal();
            } catch (err) {
                authStatus.textContent = err.message;
            }
        });

        logoutButton.addEventListener('click', async () => {
            await apiFetch('/auth/logout', {
                method: 'POST',
            }).catch(() => {});
            setAuthState('', '');
        });

         document.getElementById('startButton').addEventListener('click', () => {
         if (gameStarted) return;
         audio.ensureStarted();
         mainMenu.style.display = 'none';
         preGameScreen.style.display = 'flex';
         loadPlayerSettings();
         updateTouchControlsVisibility();
});

        confirmStart.addEventListener('click', () => {
            if (gameStarted) return;
            playerName = currentUser || 'Player';
            const selected = preGameScreen.querySelector('input[name="difficulty"]:checked');
            selectedDifficulty = selected ? selected.value : 'normal';
            localStorage.setItem('shadowdog_difficulty', selectedDifficulty);
            gameStarted = true;
            preGameScreen.style.display = 'none';
            canvas.style.display = 'block';
            if (shareScoreBtn) shareScoreBtn.style.display = 'none';
            game = new Game(canvas.width, canvas.height);// Initialize lastTime to 0
            audio.ensureStarted();
            audio.startBgm();
            applyDifficultySettings(game);
            game.player.currentState = game.player.states[0];
            game.player.currentState.enter();
            game.time = 0;
            lastTime = null;
            startGameSessionTracking();
            updateTouchControlsVisibility();
            requestAnimationFrame(animate);
        });

        cancelStart.addEventListener('click', () => {
            preGameScreen.style.display = 'none';
            mainMenu.style.display = 'flex';
            updateTouchControlsVisibility();
        });

        scoresButton.addEventListener('click', () => {
            mainMenu.style.display = 'none';
            scoresScreen.style.display = 'flex';
            renderScores();
            updateTouchControlsVisibility();
        });

        backButton.addEventListener('click', () => {
            scoresScreen.style.display = 'none';
            mainMenu.style.display = 'flex';
            updateTouchControlsVisibility();
        });

        if (adminPanelButton) {
            adminPanelButton.addEventListener('click', () => {
                openAdminPanel();
            });
        }

        if (adminStatsButton) {
            adminStatsButton.addEventListener('click', () => {
                openAdminPanel();
            });
        }

        if (adminTrend7Button) {
            adminTrend7Button.addEventListener('click', () => {
                if (selectedTrendDays === 7) return;
                selectedTrendDays = 7;
                localStorage.setItem(TREND_RANGE_STORAGE_KEY, '7');
                updateTrendRangeUI();
                if (adminScreen && adminScreen.style.display === 'flex') {
                    openAdminPanel();
                }
            });
        }

        if (adminTrend30Button) {
            adminTrend30Button.addEventListener('click', () => {
                if (selectedTrendDays === 30) return;
                selectedTrendDays = 30;
                localStorage.setItem(TREND_RANGE_STORAGE_KEY, '30');
                updateTrendRangeUI();
                if (adminScreen && adminScreen.style.display === 'flex') {
                    openAdminPanel();
                }
            });
        }

        if (adminBackButton) {
            adminBackButton.addEventListener('click', () => {
                if (adminScreen) adminScreen.style.display = 'none';
                mainMenu.style.display = 'flex';
                updateTouchControlsVisibility();
            });
        }

        if (resetScoresButton) {
            updateAdminToolsVisibility();
            resetScoresButton.addEventListener('click', async () => {
                if (!userCanSeeAdminReset()) return;
                const adminToken = await requestAdminToken('reset scores');
                if (!adminToken) return;
                const headers = {
                    'x-admin-token': adminToken.trim()
                };
                const res = await apiFetch('/scores', {
                    method: 'DELETE',
                    headers
                }).catch(() => null);
                if (!res) {
                    showToast('Network error while resetting scores.', 'error');
                    return;
                }
                if (res.status === 401) {
                    showToast('Login as admin is required.', 'error');
                    return;
                }
                if (res.status === 403) {
                    showToast('Forbidden: admin token or account is invalid.', 'error');
                    return;
                }
                if (!res.ok) {
                    showToast('Failed to reset scores.', 'error');
                    return;
                }
                renderScores();
                showToast('Scores reset successfully.', 'success');
            });
        }

        if (resetStatsButton) {
            updateAdminToolsVisibility();
            resetStatsButton.addEventListener('click', async () => {
                if (!userCanSeeAdminReset()) return;
                const adminToken = await requestAdminToken('reset statistics');
                if (!adminToken) return;
                const headers = {
                    'x-admin-token': adminToken.trim()
                };
                const res = await apiFetch('/admin/statistics', {
                    method: 'DELETE',
                    headers
                }).catch(() => null);
                if (!res) {
                    showToast('Network error while resetting statistics.', 'error');
                    return;
                }
                if (res.status === 401) {
                    showToast('Login as admin is required.', 'error');
                    return;
                }
                if (res.status === 403) {
                    showToast('Forbidden: admin token or account is invalid.', 'error');
                    return;
                }
                if (!res.ok) {
                    showToast('Failed to reset statistics.', 'error');
                    return;
                }
                showToast('Statistics reset successfully.', 'success');
                openAdminPanel();
            });
        }
        updateTouchControlsVisibility();
    });
