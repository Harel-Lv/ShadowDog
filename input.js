export class InputHandler {
    constructor(game) {
        this.game = game;
        this.keys = [];
        window.addEventListener('keydown', e => {
            if (e.code === 'KeyP' || e.key === 'p' || e.key === 'P') {
                this.game.paused = !this.game.paused;
                return;
            }
            if ((e.key === 'ArrowUp' || 
                e.key === 'ArrowDown' || 
                e.key === 'ArrowLeft' || 
                e.key === 'ArrowRight' ||
                e.key === 'Enter') 
                && this.keys.indexOf(e.key) === -1) {
                this.keys.push(e.key);
            }
        });
 // Toggle debug mode
        window.addEventListener('keyup', e => {
            if (e.key === 'ArrowUp' ||
                e.key === 'ArrowDown' ||
                e.key === 'ArrowLeft' ||
                e.key === 'ArrowRight' ||
                e.key === 'Enter') {
                const index = this.keys.indexOf(e.key);
                if (index !== -1) this.keys.splice(index, 1);
                
            }
        });
        
    }

}
