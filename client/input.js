export class InputHandler {
    constructor(game) {
        this.game = game;
        this.keys = [];
        const gameplayKeys = new Set(['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter']);
        const touchControls = document.getElementById('touchControls');
        const isTypingTarget = (target) => {
            if (!target) return false;
            const tagName = typeof target.tagName === 'string' ? target.tagName.toUpperCase() : '';
            return target.isContentEditable || tagName === 'INPUT' || tagName === 'TEXTAREA' || tagName === 'SELECT';
        };
        const pressKey = (key) => {
            if (gameplayKeys.has(key) && this.keys.indexOf(key) === -1) {
                this.keys.push(key);
            }
        };
        const releaseKey = (key) => {
            const index = this.keys.indexOf(key);
            if (index !== -1) this.keys.splice(index, 1);
        };
        window.addEventListener('keydown', e => {
            const typing = isTypingTarget(e.target);
            if (!typing && gameplayKeys.has(e.key)) e.preventDefault();
            if (typing) return;
            if (e.code === 'KeyP' || e.key === 'p' || e.key === 'P') {
                this.game.paused = !this.game.paused;
                return;
            }
            pressKey(e.key);
        });
        window.addEventListener('keyup', e => {
            if (gameplayKeys.has(e.key)) {
                const typing = isTypingTarget(e.target);
                if (!typing) e.preventDefault();
                releaseKey(e.key);
                
            }
        });

        if (touchControls) {
            touchControls.addEventListener('contextmenu', (e) => e.preventDefault());
            const buttons = touchControls.querySelectorAll('[data-key]');
            buttons.forEach((btn) => {
                const key = btn.dataset.key;
                const handleDown = (e) => {
                    if (e.cancelable) e.preventDefault();
                    btn.classList.add('is-pressed');
                    pressKey(key);
                };
                const handleUp = (e) => {
                    if (e.cancelable) e.preventDefault();
                    btn.classList.remove('is-pressed');
                    releaseKey(key);
                };
                btn.addEventListener('pointerdown', handleDown, { passive: false });
                btn.addEventListener('pointerup', handleUp, { passive: false });
                btn.addEventListener('pointercancel', handleUp, { passive: false });
                btn.addEventListener('pointerleave', handleUp, { passive: false });
                btn.addEventListener('touchstart', handleDown, { passive: false });
                btn.addEventListener('touchend', handleUp, { passive: false });
                btn.addEventListener('touchcancel', handleUp, { passive: false });
            });
        }
        
    }

}
