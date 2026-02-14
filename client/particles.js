class Particle {
    constructor(game) {
        this.game = game;
        this.markForDeletion = false; // Flag to mark this object for deletion
        // Initialization code
    }

    update() {
        const scale = this.game.frameScale || 1;
        // Update logic
        this.x -= (this.game.speed + this.speedX) * scale;
        this.y -= this.speedY * scale; // Move the object based on game speed
        this.size = this.size * Math.pow(0.9, scale);
        if (this.size < 0.5) {
            this.markForDeletion = true; // Mark for deletion if size is too small
        }
    }
}

export class Dust extends Particle {
    constructor(game, x, y) {
        super(game);
        this.x = x;
        this.y = y;
        this.size = 10 + Math.random() * 10; // Random size between 20 and 40
        this.speedX = Math.random() * 2; // Random horizontal speed
        this.speedY = Math.random() * 2; // Random vertical speed
        this.color = 'black'
    }

    draw(context) {
        context.beginPath();
        context.arc(this.x, this.y, this.size, 0, Math.PI * 2); // Draw a circle
        context.fillStyle = this.color;
        context.fill();
    }
}
export class Fire extends Particle {
    constructor(game, x, y) {
        super(game);
        this.image = document.getElementById('fire');
        this.x = x;
        this.y = y;
        this.size = 28 + Math.random() * 34;
        this.speedX = 1;
        this.speedY = 1; 
    }
    update() {
        super.update();
    }

    draw(context) {
        context.drawImage(this.image, this.x, this.y, this.size, this.size); // Draw the fire image
    }
}

export class Splash extends Particle {
    constructor(game, x, y) {
        super(game);
        this.size = 26 + Math.random() * 30;
        this.x = x - this.size * 0.5; // Spawn around collision center
        this.y = y - this.size * 0.5; // Spawn around collision center
        this.gravity = 1; // Gravity effect for splash
        this.speedX = Math.random() * 6 - 3; // Random horizontal speed
        this.speedY = Math.random() * 2 + 2; // Random vertical speed 
        this.image = document.getElementById('fire');
    }
    update() {
        super.update();
        const scale = this.game.frameScale || 1;
        this.gravity += 0.1 * scale; // Increase gravity effect
        this.y += this.gravity * scale; // Apply gravity to vertical position
    }

    draw(context) {
        context.drawImage(this.image, this.x, this.y, this.size, this.size); // Draw the splash image
    }
}
