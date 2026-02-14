export class Score {
    constructor(game) {
        this.game = game;
        this.fontSize = 30;
        this.fontFamily = 'Arial';
        this.ui = {
            scoreX: 20,
            scoreY: 50,
            timeY: 80,
            heartsX: 25,
            heartsY: 100,
            heartSize: 30,
            heartsSpacing: 35,
            staminaX: 20,
            staminaY: 140,
            staminaWidth: 150,
            staminaHeight: 10,
        };
    }

    draw(context) {
        context.fillStyle = '#f5f7fa';
        context.strokeStyle = 'rgba(0, 0, 0, 0.75)';
        context.lineWidth = 3;
        context.textAlign = 'left';
        context.font = this.fontSize + 'px ' + this.fontFamily;

        context.fillText(`Score: ${this.game.score}`, this.ui.scoreX, this.ui.scoreY);
        context.strokeText(`Score: ${this.game.score}`, this.ui.scoreX, this.ui.scoreY);
        context.fillText(`Distance: ${Math.floor(this.game.distance)} / ${this.game.targetDistance}`, this.ui.scoreX, this.ui.timeY);
        context.strokeText(`Distance: ${Math.floor(this.game.distance)} / ${this.game.targetDistance}`, this.ui.scoreX, this.ui.timeY);
        context.textAlign = 'right';
        const remainingSeconds = Math.max(0, Math.floor((this.game.maxtime - this.game.time) / 1000));
        context.fillText(`Time: ${remainingSeconds}`, this.game.width - 20, this.ui.scoreY);
        context.strokeText(`Time: ${remainingSeconds}`, this.game.width - 20, this.ui.scoreY);
        context.textAlign = 'left';

        if (this.game.gameOver) {
            context.textAlign = 'center';
            const message = this.game.distance >= this.game.targetDistance ? 'You Win!' : 'Game Over';
            context.fillText(message, this.game.width / 2, this.game.height / 2);
            context.strokeText(message, this.game.width / 2, this.game.height / 2);
        }
        if (this.game.paused) {
            context.fillStyle = 'rgba(0, 0, 0, 0.5)'; // Dim background
            context.fillRect(0, 0, this.game.width, this.game.height);

            context.fillStyle = 'Black'; // Pause label
            context.font = 'bold 40px Arial';
            context.textAlign = 'center';
            context.fillText('PAUSED', this.game.width / 2, this.game.height / 2);
        }
        for (let i = 0; i < this.game.lives; i++) {
            context.drawImage(
                document.getElementById('heart1'), // Heart icon
                this.ui.heartsX + i * this.ui.heartsSpacing, // Icon spacing
                this.ui.heartsY, // Fixed Y under score
                this.ui.heartSize, this.ui.heartSize // Icon size
            );
        }
        // Stamina bar
        context.fillStyle = 'black';
        context.fillRect(this.ui.staminaX, this.ui.staminaY, this.ui.staminaWidth, this.ui.staminaHeight); // Background

        context.fillStyle = 'limegreen';
        const staminaWidth = (this.game.player.stamina / this.game.player.maxStamina) * this.ui.staminaWidth;
        context.fillRect(this.ui.staminaX, this.ui.staminaY, staminaWidth, this.ui.staminaHeight); // Fill

        context.strokeStyle = 'white';
        context.strokeRect(this.ui.staminaX, this.ui.staminaY, this.ui.staminaWidth, this.ui.staminaHeight); // Border
    }
}
