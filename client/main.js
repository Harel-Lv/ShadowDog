import { Player } from "./player.js";
import { InputHandler } from "./input.js";
import { BackGround } from "./BackGround.js";
import { FlyingEnemy, ClimbingEnemy , GroundEnemy } from "./enemies/enemies.js";
import { Score } from "./score.js";



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
        const scoresButton = document.getElementById('scoresButton');
        const scoresScreen = document.getElementById('scoresScreen');
        const scoresListEasy = document.getElementById('scoresListEasy');
        const scoresListNormal = document.getElementById('scoresListNormal');
        const scoresListHard = document.getElementById('scoresListHard');
        const backButton = document.getElementById('backButton');
        const resetScoresButton = document.getElementById('resetScoresButton');
        const runtimeConfig = window.SHADOWDOG_CONFIG || {};
        const adminUsername = String(runtimeConfig.adminUsername || window.ADMIN_USERNAME || 'harel').trim().toLowerCase();
        const isAdmin = window.IS_ADMIN === true ||
            window.IS_ADMIN === 'true' ||
            window.IS_ADMIN === 1 ||
            window.IS_ADMIN === '1';
        const openSignupButton = document.getElementById('openSignupButton');
        const openLoginButton = document.getElementById('openLoginButton');
        const authUsernameInput = document.getElementById('authUsername');
        const authPasswordInput = document.getElementById('authPassword');
        const authModal = document.getElementById('authModal');
        const authModalTitle = document.getElementById('authModalTitle');
        const authSubmitButton = document.getElementById('authSubmitButton');
        const authCancelButton = document.getElementById('authCancelButton');
        const logoutButton = document.getElementById('logoutButton');
        const authStatus = document.getElementById('authStatus');
        const authStatusTop = document.getElementById('authStatusTop');
        const toast = document.getElementById('toast');
        const mainMenu = document.getElementById('mainMenu');
        const preGameScreen = document.getElementById('preGameScreen');
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
        const MAX_ENEMIES = 14;
        const MAX_PARTICLES = 280;
        const DEFAULT_TARGET_DISTANCE = 200;
        const DIFFICULTY_SETTINGS = {
            easy: { targetDistance: 100, enemyMultiplier: 2, minEnemyInterval: 600 },
            normal: { targetDistance: 200, enemyMultiplier: 1, minEnemyInterval: 400 },
            hard: { targetDistance: 250, enemyMultiplier: 2 / 3, minEnemyInterval: 260 }
        };
        let selectedDifficulty = 'normal';
        let playerName = 'Player';
        const AUTH_TOKEN_KEY = 'shadowdog_auth_token';
        const AUTH_USER_KEY = 'shadowdog_auth_user';
        const previousLocalToken = localStorage.getItem(AUTH_TOKEN_KEY) || '';
        const previousLocalUser = localStorage.getItem(AUTH_USER_KEY) || '';
        let authToken = sessionStorage.getItem(AUTH_TOKEN_KEY) || previousLocalToken;
        let currentUser = sessionStorage.getItem(AUTH_USER_KEY) || previousLocalUser;
        let authMode = 'login';
        let toastTimer = null;

        const configuredApiBase = window.API_BASE || runtimeConfig.apiBase || '';
        const localhostFallback = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
            ? 'http://127.0.0.1:3002'
            : 'https://shadowdog-api.onrender.com';
        const API_BASE = String(configuredApiBase || localhostFallback).replace(/\/+$/, '');
        const apiUrl = (path) => `${API_BASE}${path}`;

        if (previousLocalToken && !sessionStorage.getItem(AUTH_TOKEN_KEY)) {
            sessionStorage.setItem(AUTH_TOKEN_KEY, previousLocalToken);
            sessionStorage.setItem(AUTH_USER_KEY, previousLocalUser);
            localStorage.removeItem(AUTH_TOKEN_KEY);
            localStorage.removeItem(AUTH_USER_KEY);
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

        function setAuthState(token, username) {
            authToken = token || '';
            currentUser = username || '';
            if (authToken) {
                sessionStorage.setItem(AUTH_TOKEN_KEY, authToken);
                sessionStorage.setItem(AUTH_USER_KEY, currentUser);
                localStorage.removeItem(AUTH_TOKEN_KEY);
                localStorage.removeItem(AUTH_USER_KEY);
                authStatus.textContent = `Logged in as ${currentUser}`;
                authStatusTop.textContent = currentUser;
                openSignupButton.style.display = 'none';
                openLoginButton.style.display = 'none';
                logoutButton.style.display = 'inline-block';
            } else {
                sessionStorage.removeItem(AUTH_TOKEN_KEY);
                sessionStorage.removeItem(AUTH_USER_KEY);
                localStorage.removeItem(AUTH_TOKEN_KEY);
                localStorage.removeItem(AUTH_USER_KEY);
                authStatus.textContent = 'Guest mode (scores will not be saved)';
                authStatusTop.textContent = 'Guest';
                openSignupButton.style.display = 'inline-block';
                openLoginButton.style.display = 'inline-block';
                logoutButton.style.display = 'none';
            }
            updateAdminResetVisibility();
        }

        function userCanSeeAdminReset() {
            const loggedInAdmin = Boolean(currentUser) && currentUser.trim().toLowerCase() === adminUsername;
            return isAdmin || loggedInAdmin;
        }

        function updateAdminResetVisibility() {
            if (!resetScoresButton) return;
            resetScoresButton.style.display = userCanSeeAdminReset() ? 'inline-block' : 'none';
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

        async function authRequest(path, payload) {
            let res;
            try {
                res = await fetch(apiUrl(path), {
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

        async function saveScore(game) {
            if (!authToken) return false;
            const entry = {
                score: game.score,
                difficulty: game.difficulty
            };
            try {
                const res = await fetch(apiUrl('/scores'), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
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
                    const res = await fetch(apiUrl(`/scores?difficulty=${difficulty}&limit=50`));
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
                data.forEach((score) => {
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
            }

            update(deltaTime) {
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
            const deltaTime = timeStamp - lastTime;
            lastTime = timeStamp; // Convert to seconds
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            if(!game.paused) {
                game.update(deltaTime);
            }
            if (game.gameOver) {
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
            }

            game.draw(ctx);
            
            if (!game.gameOver) requestAnimationFrame(animate);
        }

         restartBtn.addEventListener('click', () => {
             location.reload(); // Reload the game on button click
         });

        setAuthState(authToken, currentUser);

        openSignupButton.addEventListener('click', () => openAuthModal('signup'));
        openLoginButton.addEventListener('click', () => openAuthModal('login'));
        authCancelButton.addEventListener('click', closeAuthModal);
        authModal.addEventListener('click', (event) => {
            if (event.target === authModal) closeAuthModal();
        });
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
                const data = await authRequest(path, { username, password });
                setAuthState(data.token, data.user?.username || username);
                closeAuthModal();
            } catch (err) {
                authStatus.textContent = err.message;
            }
        });

        logoutButton.addEventListener('click', async () => {
            if (authToken) {
                await fetch(apiUrl('/auth/logout'), {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                }).catch(() => {});
            }
            setAuthState('', '');
        });

         document.getElementById('startButton').addEventListener('click', () => {
         if (gameStarted) return;
         mainMenu.style.display = 'none';
         preGameScreen.style.display = 'flex';
         loadPlayerSettings();
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
            game = new Game(canvas.width, canvas.height);// Initialize lastTime to 0
            applyDifficultySettings(game);
            game.player.currentState = game.player.states[0];
            game.player.currentState.enter();
            game.time = 0;
            lastTime = null;
            requestAnimationFrame(animate);
        });

        cancelStart.addEventListener('click', () => {
            preGameScreen.style.display = 'none';
            mainMenu.style.display = 'flex';
        });

        scoresButton.addEventListener('click', () => {
            mainMenu.style.display = 'none';
            scoresScreen.style.display = 'flex';
            renderScores();
        });

        backButton.addEventListener('click', () => {
            scoresScreen.style.display = 'none';
            mainMenu.style.display = 'flex';
        });

        if (resetScoresButton) {
            updateAdminResetVisibility();
            resetScoresButton.addEventListener('click', async () => {
                if (!userCanSeeAdminReset()) return;
                const adminToken = window.prompt('Admin token required to reset scores:');
                if (!adminToken) return;
                const headers = {
                    'x-admin-token': adminToken.trim()
                };
                if (authToken) headers.Authorization = `Bearer ${authToken}`;
                const res = await fetch(apiUrl('/scores'), {
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
    });
