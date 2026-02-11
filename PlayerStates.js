import { Dust, Fire, Splash } from "./praticale.js";

const States = {
    SITTING: 0,
    RUNNING: 1,
    JUMPING: 2,
    FALLING: 3,
    ROLLING: 4,
    DIVING: 5,
    HIT :6


};

class State {
    constructor(state, game) {
        this.state = state;
        this.game = game;
    }
}
export class Sitting extends State {
    constructor(game) {
        super("SITTING", game);

    }

    enter() {
        this.game.player.frameX = 0; // Reset horizontal frame index for sitting state
       this.game.player.frameY = 5; // Set the frame for sitting state
       this.game.player.maxFrame = 4; // Set the maximum frame for sitting state
    }

    handleInput(input) {
        if (input.includes('ArrowRight') || input.includes('ArrowLeft')) {
            this.game.player.setState(States.RUNNING, 1);
        }
        else if (input.includes('ArrowUp')) {
            this.game.player.setState(States.JUMPING, 1);
        }
        else if (input.includes('Enter')&& this.game.player.stamina > 10) {
            this.game.player.setState(States.ROLLING, 2);
        }
    }
}

export class Running extends State {
    constructor(game) {
        super("RUNNING", game);
    }

    enter() {
        this.game.player.frameX = 0; 
        this.game.player.frameY = 3;
        this.game.player.maxFrame = 6; // Set the maximum frame for running state
    }

    handleInput(input) {
        this.game.particles.push(new Dust(this.game, this.game.player.x + this.game.player.width * 0.5, this.game.player.y + this.game.player.height));
        if (input.includes('ArrowDown')) {
            this.game.player.setState(States.SITTING, 0);
        } else if (input.includes('ArrowUp')) {
            this.game.player.setState(States.JUMPING, 1);
        }
        else if (input.includes('Enter')&& this.game.player.stamina > 10) {
            this.game.player.setState(States.ROLLING, 2);
        }
    }
}

export class Jumping extends State {
    constructor(game) {
        super("JUMPING", game);
    }

    enter() {
// Set the frame for jumping state
        this.game.player.frameX = 0; // Reset horizontal frame index for jumping state
        if (this.game.player.onGround()) this.game.player.vy = this.game.player.jumpVelocity; // Jumping effect

        this.game.player.frameY = 1;
        this.game.player.maxFrame = 6; // Set the maximum frame for jumping state
    }

    handleInput(input) {
        if (this.game.player.vy > this.game.player.weight) {
            this.game.player.setState(States.FALLING, 1);
        }
        else if (input.includes('Enter')&& this.game.player.stamina > 0) {
            this.game.player.setState(States.ROLLING, 2);
        }
        else if (input.includes('ArrowDown')) {
            this.game.player.setState(States.DIVING, 0);
        }
    }
}

export class Falling extends State {
    constructor(game) {
        super("FALLING", game);
    }

    enter() {
        this.game.player.frameX = 0;
        this.game.player.frameY = 2;
        this.game.player.maxFrame = 6; // Set the maximum frame for falling state
    }

    handleInput(input) {
        if (this.game.player.onGround()) {
            this.game.player.setState(States.RUNNING, 1);
        }
        else if (input.includes('Enter') && this.game.player.stamina > 0) {
            this.game.player.setState(States.ROLLING, 2);
        }
        else if (input.includes('ArrowDown') && this.game.player.stamina > 0) {
            this.game.player.setState(States.DIVING, 0);
        }
    }
}

export class Rolling extends State {
    constructor(game) {
        super("ROLLING", game)
    }

    enter() {
        this.game.player.frameX = 0;
        this.game.player.frameY = 6;
        this.game.player.maxFrame = 6; // Set the maximum frame for falling state
    }

    handleInput(input) {
        this.game.particles.push(new Fire(this.game, this.game.player.x + this.game.player.width * 0.05, this.game.player.y + this.game.player.height*0.05));
        if (input.includes('ArrowDown')) {
            this.game.player.setState(States.SITTING, 0);
        } else if ((this.game.player.onGround() && !input.includes('Enter')) || this.game.player.stamina <= 0) {
            this.game.player.setState(States.RUNNING, 1);
            for (let i = 0; i < 30; i++) {
            this.game.particles.unshift(new Splash(this.game, this.game.player.x + this.game.player.width * 0.5, this.game.player.y + this.game.player.height * 0.5));
            }
        }
        else if ((!this.game.player.onGround() && !input.includes('Enter')) || this.game.player.stamina <= 0) {
            this.game.player.setState(States.FALLING, 1);
        }
        else if (input.includes('ArrowUp') && this.game.player.onGround() && input.includes('Enter')) {
            this.game.player.vy = this.game.player.jumpVelocity; // Jumping effect while rolling
        }
        else if (input.includes('ArrowDown') && this.game.player.stamina > 0) {
            this.game.player.setState(States.DIVING, 0);
        }
    }
}

export class Diving extends State {
    constructor(game) {
        super("DIVING", game)
    }

    enter() {
        this.game.player.frameX = 0;
        this.game.player.frameY = 6;
        this.game.player.maxFrame = 6; // Set the maximum frame for falling state
    }

    handleInput(input) {
        this.game.particles.push(new Fire(this.game, this.game.player.x + this.game.player.width * 0.05, this.game.player.y + this.game.player.height*0.05));
        if (this.game.player.onGround()) {
            if (input.includes('Enter') && this.game.player.stamina > 0) {
                this.game.player.setState(States.ROLLING, 2);
            } else {
                this.game.player.setState(States.RUNNING, 1);
            }
        }
    }
}

export class Hit extends State {
    constructor(game) {
        super("HIT", game)
    }

    enter() {
        this.game.player.frameX = 0;
        this.game.player.frameY = 4;
        this.game.player.maxFrame = 10; // Set the maximum frame for falling state
        const hitDuration = this.game.player.frameInterval * (this.game.player.maxFrame + 1);
        this.game.hitFreezeTimer = hitDuration;
        this.game.invulnTimer = hitDuration;
    }

    handleInput(input) {
        if (this.game.player.onGround() && this.game.player.frameX >= 10) {
            this.game.player.setState(States.RUNNING, 1);
        }
        else if (!this.game.player.onGround() && this.game.player.frameX >= 10) {
            this.game.player.setState(States.FALLING, 1);
        }
    }
}
