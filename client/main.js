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
        const playerNameInput = document.getElementById('playerName');
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
        const DEFAULT_TARGET_DISTANCE = 200;
        const DIFFICULTY_SETTINGS = {
            easy: { targetDistance: 100, enemyMultiplier: 2 },
            normal: { targetDistance: 200, enemyMultiplier: 1 },
            hard: { targetDistance: 250, enemyMultiplier: 2 / 3 }
        };
        let selectedDifficulty = 'normal';
        let playerName = 'Player';
        let authToken = localStorage.getItem('shadowdog_auth_token') || '';
        let currentUser = localStorage.getItem('shadowdog_auth_user') || '';
        let authMode = 'login';
        let toastTimer = null;

        const API_BASE = window.API_BASE || 'http://localhost:3001';

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
                localStorage.setItem('shadowdog_auth_token', authToken);
                localStorage.setItem('shadowdog_auth_user', currentUser);
                authStatus.textContent = `Logged in as ${currentUser}`;
                authStatusTop.textContent = currentUser;
                logoutButton.style.display = 'inline-block';
                if (currentUser) playerNameInput.value = currentUser;
            } else {
                localStorage.removeItem('shadowdog_auth_token');
                localStorage.removeItem('shadowdog_auth_user');
                authStatus.textContent = 'Guest mode (scores will not be saved)';
                authStatusTop.textContent = 'Guest';
                logoutButton.style.display = 'none';
            }
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
            const res = await fetch(`${API_BASE}${path}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
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
                const res = await fetch(`${API_BASE}/scores`, {
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
            let scores = [];
            try {
                const res = await fetch(`${API_BASE}/scores?limit=50`);
                scores = res.ok ? await res.json() : [];
            } catch {
                scores = [];
            }
            const byDifficulty = {
                easy: scores.filter(s => s.difficulty === 'easy'),
                normal: scores.filter(s => s.difficulty === 'normal'),
                hard: scores.filter(s => s.difficulty === 'hard')
            };
            const lists = [
                { list: scoresListEasy, data: byDifficulty.easy },
                { list: scoresListNormal, data: byDifficulty.normal },
                { list: scoresListHard, data: byDifficulty.hard }
            ];
            lists.forEach(({ list, data }) => {
                list.innerHTML = '';
                const sorted = data.slice().sort((a, b) => {
                    const scoreDiff = (b.score ?? 0) - (a.score ?? 0);
                    if (scoreDiff !== 0) return scoreDiff;
                    const aTime = Date.parse(a.created_at || '');
                    const bTime = Date.parse(b.created_at || '');
                    if (Number.isNaN(aTime) || Number.isNaN(bTime)) return 0;
                    return aTime - bTime;
                });
                if (sorted.length === 0) {
                    const li = document.createElement('li');
                    li.textContent = 'No scores yet';
                    list.appendChild(li);
                    return;
                }
                sorted.forEach((score, index) => {
                    const li = document.createElement('li');
                    const name = score.name || 'Player';
                    li.textContent = `${index + 1}. ${name} - SCORE: ${score.score ?? 0}`;
                    list.appendChild(li);
                });
            });
        }

        function loadPlayerSettings() {
            const savedName = localStorage.getItem('shadowdog_player_name');
            const savedDifficulty = localStorage.getItem('shadowdog_difficulty');
            if (currentUser) playerNameInput.value = currentUser;
            else if (savedName) playerNameInput.value = savedName;
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
            const scaledMin = BASE_MIN_INTERVAL * settings.enemyMultiplier;
            gameInstance.minEnemyInterval = Math.min(MAX_MIN_INTERVAL, Math.max(BASE_MIN_INTERVAL, scaledMin));
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
                this.hitFreezeDuration = 1000;
                this.invulnDuration = 1000;
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
                if (this.speed >0 && Math.random() < 0.5) {
                    this.enemies.push(new GroundEnemy(this));
                }
                else if (this.speed > 0) {
                    this.enemies.push(new ClimbingEnemy(this));
                }
                this.enemies.push(new FlyingEnemy(this));
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
                restartBtn.style.display = 'block'; // מציג את כפתור האתחול
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
                await fetch(`${API_BASE}/auth/logout`, {
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
         playerNameInput.focus();
});

        confirmStart.addEventListener('click', () => {
            if (gameStarted) return;
            const name = playerNameInput.value.trim();
            playerName = name.length > 0 ? name : 'Player';
            const selected = preGameScreen.querySelector('input[name="difficulty"]:checked');
            selectedDifficulty = selected ? selected.value : 'normal';
            localStorage.setItem('shadowdog_player_name', playerName);
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

        if (isAdmin && resetScoresButton) {
            resetScoresButton.style.display = 'inline-block';
            resetScoresButton.addEventListener('click', async () => {
                const adminToken = window.prompt('Admin token required to reset scores:');
                if (!adminToken) return;
                const res = await fetch(`${API_BASE}/scores`, {
                    method: 'DELETE',
                    headers: { 'x-admin-token': adminToken.trim() }
                }).catch(() => null);
                if (!res) {
                    showToast('Network error while resetting scores.', 'error');
                    return;
                }
                if (res.status === 403) {
                    showToast('Forbidden: admin token is invalid.', 'error');
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
