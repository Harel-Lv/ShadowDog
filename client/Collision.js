export class Collision {
    constructor(game, x, y) {
        this.game = game;
        this.image = document.getElementById('boom');
        this.spriteWidth = 200;
        this.spriteHeight = 300;
        this.sizeModifier = 0.5; // Size modifier for the explosion
        this.width = this.spriteWidth * this.sizeModifier;
        this.height = this.spriteHeight * this.sizeModifier;
        this.x = x - this.width * 0.5; // Center the explosion
        this.y = y - this.width * 0.5; // Center the explosion
        this.frameX = 0; // Horizontal frame index for sprite animation
        this.maxFrame = 4; // Maximum frame for explosion animation
        this.markForDeletion = false; // Flag to mark the explosion for deletion
        this.frameTimer = 0; // Timer to control frame updates
        this.fps = 20; // Frames per second for animation
        this.frameInterval = 1000 / this.fps; // Interval between frames in milliseconds
    }
    update(deltaTime) {
        this.x -= this.game.speed;
        if (this.frameTimer > this.frameInterval) {
            this.frameX++; // Move to the next frame
            this.frameTimer = 0; // Reset timer
        }
        else this.frameTimer += deltaTime; // Increment timer by deltaTime

        if (this.frameX > this.maxFrame) {
            this.markForDeletion = true; // Mark the explosion for deletion after the last frame
        }

    }
    draw(context) {
        context.drawImage(this.image, this.frameX * this.spriteWidth, 0, this.spriteWidth, this.spriteHeight, this.x, this.y, this.width, this.height);
    }
    
}
