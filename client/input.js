export class InputHandler {
    constructor(game) {
        this.game = game;
        this.keys = [];
        const gameplayKeys = new Set(['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter']);
        const isTypingTarget = (target) => {
            if (!target) return false;
            const tagName = typeof target.tagName === 'string' ? target.tagName.toUpperCase() : '';
            return target.isContentEditable || tagName === 'INPUT' || tagName === 'TEXTAREA' || tagName === 'SELECT';
        };
        window.addEventListener('keydown', e => {
            const typing = isTypingTarget(e.target);
            if (!typing && gameplayKeys.has(e.key)) e.preventDefault();
            if (typing) return;
            if (e.code === 'KeyP' || e.key === 'p' || e.key === 'P') {
                this.game.paused = !this.game.paused;
                return;
            }
            if (gameplayKeys.has(e.key) && this.keys.indexOf(e.key) === -1) {
                this.keys.push(e.key);
            }
        });
        window.addEventListener('keyup', e => {
            if (gameplayKeys.has(e.key)) {
                const typing = isTypingTarget(e.target);
                if (!typing) e.preventDefault();
                const index = this.keys.indexOf(e.key);
                if (index !== -1) this.keys.splice(index, 1);
                
            }
        });
        
    }

}
