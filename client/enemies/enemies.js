class Enemy {
    constructor() {
       this.frameX = 0; // Horizontal frame index for sprite animation
       this.frameY = 0;
       this.fps = 20;
       this.frameInterval = 1000 / this.fps;
       this.frameTimer = 0;
         this.markForDeletion = false; // Flag to mark the enemy for deletion
    }
    update(deltaTime) {
       const scale = this.game.frameScale || 1;
       this.x -= (this.speedX + this.game.speed) * scale; // Move the enemy horizontally
       this.y += this.speedY * scale; // Move the enemy vertically

         // Handle animation frame updates
         if (this.frameTimer > this.frameInterval) {
              this.frameTimer = 0; // Reset timer
              if (this.frameX < this.maxFrame) this.frameX++;
              else this.frameX = 0; // Move to the next frame
         }
         else this.frameTimer += deltaTime; // Increment timer by deltaTime

            // Check if the enemy is off-screen
         if (this.x + this.width < 0) {
           this.markForDeletion = true; // Remove the enemy from the game
         }

    }
    draw(context) {
        if (this.x + this.width < 0 || this.x > this.game.width) return;
        context.drawImage(this.image,this.frameX * this.width,0, this.width, this.height,this.x, 
        this.y, this.width, this.height);
    }
}

export class FlyingEnemy extends Enemy {
    constructor(game) {
        super();
        this.game = game;
        this.width = 60;
        this.height = 40;
        this.x = this.game.width + Math.random() * this.game.width * 0.4; // Start at the right edge of the canvas
        this.y = Math.random() * this.game.height * 0.5; // Adjusted y position for flying enemy
        this.speedX = 2; // Speed of the flying enemy
        this.speedY = 0; // No vertical movement for flying enemy
        this.maxFrame = 5; // Maximum frame for animation
        this.image = document.getElementById('enemy_fly'); // Image for flying enemy
        this.angle = 0; // Random angle for flying enemy
        this.angleSpeed = 0.1 + Math.random() * 0.1;
    }
    update(deltaTime) {
        super.update(deltaTime); // Call the parent update method
        // Additional logic for flying enemy can be added here
        const scale = this.game.frameScale || 1;
        this.angle += this.angleSpeed * scale; // Update angle for flying enemy
        this.y += Math.sin(this.angle) * scale; // Sinusoidal vertical movement

    }

}

export class GroundEnemy extends Enemy {
    constructor(game) {
        super();
        this.game = game;
        this.width = 60;
        this.height = 87;
        this.x = this.game.width; // Start at the right edge of the canvas
        this.y = this.game.height - this.height - this.game.groundMargin; // Adjusted y position for ground enemy
        this.speedX = 0; // Speed of the ground enemy
        this.speedY = 0; // No vertical movement for ground enemy
        this.maxFrame = 1; // Maximum frame for animation
        this.image = document.getElementById('enemy_plant'); // Image for ground enemy
    }
   
}

export class ClimbingEnemy extends Enemy {
    constructor(game) {
        super();
        this.game = game;
        this.width = 120;
        this.height = 144;
        this.x = this.game.width; // Start at the right edge of the canvas
        this.y = Math.random() * (this.game.height * 0.5); // Random y position for climbing enemy
        this.speedX = 0; // Speed of the climbing enemy
        this.speedY = Math.random() > 0.5 ? 1 : -1; // Random vertical speed for climbing enemy
        this.maxFrame = 1; // Maximum frame for animation
        this.image = document.getElementById('enemy_spider'); // Image for climbing enemy
        this.maxFrame = 5; // Maximum frame for climbing enemy
    }
    update(deltaTime) {
        super.update(deltaTime); // Call the parent update method
        // Additional logic for climbing enemy can be added here
        if (this.y < 0 || this.y + this.height > this.game.height - this.game.groundMargin) {
            this.speedY *= -1; // Reverse direction if hitting top or bottom
        }
    }
   draw(context) {
        super.draw(context); // Call the parent draw method
        if (this.x + this.width < 0 || this.x > this.game.width) return;
        context.beginPath();
        context.moveTo(this.x + this.width / 2, 0);
        context.lineTo(this.x + this.width/2, this.y + 50);
        context.stroke();
    }
}                                                               
