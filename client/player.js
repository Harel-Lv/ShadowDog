import { Sitting, Running, Jumping, Falling, Rolling, Diving, Hit } from "./PlayerStates.js";
import { Collision } from "./Collision.js";

const PLAYER_CONFIG = {
  width: 100,
  height: 91.3,
  weight: 1,
  maxSpeed: 10,
  fps: 20,
  staminaMax: 100,
  staminaRecovery: 10,
  staminaDrainRate: 50,
  jumpVelocity: -27,
};

export class Player {
  constructor(game) {
    this.game = game;
    this.jumpVelocity = PLAYER_CONFIG.jumpVelocity;
    this.width = PLAYER_CONFIG.width;
    this.height = PLAYER_CONFIG.height;
    this.x = 0;
    this.y = this.game.height - this.height - this.game.groundMargin;
    this.vy = 0;
    this.weight = PLAYER_CONFIG.weight;
    this.image = document.getElementById("player");
    this.speed = 0;
    this.frameX = 0;
    this.frameY = 0;
    this.maxSpeed = PLAYER_CONFIG.maxSpeed;
    this.maxFrame = 5;
    this.fps = PLAYER_CONFIG.fps;
    this.frameInterval = 1000 / this.fps;
    this.frameTimer = 0;
    this.states = [
      new Sitting(this.game),
      new Running(this.game),
      new Jumping(this.game),
      new Falling(this.game),
      new Rolling(this.game),
      new Diving(this.game),
      new Hit(this.game),
    ];
    this.stamina = PLAYER_CONFIG.staminaMax;
    this.maxStamina = PLAYER_CONFIG.staminaMax;
    this.staminaRecovery = PLAYER_CONFIG.staminaRecovery;
    this.staminaDrainRate = PLAYER_CONFIG.staminaDrainRate;
    this.effectCooldowns = {};
  }

  update(input, deltaTime) {
    this.checkCollision();
    const scale = this.game.frameScale || 1;
    const canMove = this.game.hitFreezeTimer <= 0;
    const inputToUse = canMove ? input : [];

    this.currentState.handleInput(inputToUse, deltaTime);

    if (canMove) {
      if (inputToUse.includes("ArrowLeft")) this.speed = -this.maxSpeed;
      else if (inputToUse.includes("ArrowRight")) this.speed = this.maxSpeed;
      else this.speed = 0;

      this.x += this.speed * scale;
      if (this.x < 0) this.x = 0;
      if (this.x > this.game.width - this.width) this.x = this.game.width - this.width;
    } else {
      this.speed = 0;
    }

    this.y += this.vy * scale;
    if (!this.onGround()) this.vy += this.weight * scale;
    else this.vy = 0;

    if (this.frameTimer > this.frameInterval) {
      this.frameTimer = 0;
      this.frameX++;
      if (this.frameX > this.maxFrame) this.frameX = 0;
    } else {
      this.frameTimer += deltaTime;
    }

    if (this.game.hitFreezeTimer <= 0) {
      if (this.currentState !== this.states[4] && this.currentState !== this.states[5]) {
        this.stamina += this.staminaRecovery * (deltaTime / 1000);
        if (this.stamina > this.maxStamina) this.stamina = this.maxStamina;
      } else {
        this.stamina -= this.staminaDrainRate * (deltaTime / 1000);
        if (this.stamina < 0) this.stamina = 0;
      }
    }
  }

  draw(context) {
    context.drawImage(
      this.image,
      this.frameX * this.width,
      this.frameY * this.height,
      this.width,
      this.height,
      this.x,
      this.y,
      this.width,
      this.height
    );
  }

  onGround() {
    return this.y >= this.game.height - this.height - this.game.groundMargin;
  }

  setState(state, speed) {
    this.currentState = this.states[state];
    this.game.speed = this.game.maxSpeed * speed;
    this.currentState.enter();
  }

  shouldEmitEffect(name, intervalMs, deltaTime) {
    const current = this.effectCooldowns[name] || 0;
    const remaining = current - deltaTime;
    if (remaining <= 0) {
      this.effectCooldowns[name] = intervalMs;
      return true;
    }
    this.effectCooldowns[name] = remaining;
    return false;
  }

  checkCollision() {
    const enemies = this.game.enemies;
    if (enemies.length === 0) return;

    for (let i = 0; i < enemies.length; i++) {
      const enemy = enemies[i];
      if (enemy.markForDeletion) continue;
      if (enemy.x > this.x + this.width || enemy.x + enemy.width < this.x) continue;
      if (enemy.y > this.y + this.height || enemy.y + enemy.height < this.y) continue;

      if (this.currentState === this.states[5] || this.currentState === this.states[4]) {
        enemy.markForDeletion = true;
        this.game.collision.push(new Collision(this.game, enemy.x + enemy.width * 0.5, enemy.y + enemy.height * 0.5));
        this.game.score++;
        this.game.audio?.playEnemyDown();
      } else {
        if (this.game.invulnTimer > 0) {
          enemy.markForDeletion = true;
          continue;
        }
        enemy.markForDeletion = true;
        this.game.collision.push(new Collision(this.game, enemy.x + enemy.width * 0.5, enemy.y + enemy.height * 0.5));
        this.setState(6, 0);
        this.game.audio?.playHit();
        this.game.lives--;
        if (this.game.lives <= 0) {
          this.game.gameOver = true;
        }
      }
    }
  }
}
