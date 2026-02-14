const BGM_PATTERN = [110, 98, 130.81, 146.83, 110, 164.81, 130.81, 98];

export class GameAudio {
  constructor({ muted = false } = {}) {
    this.muted = Boolean(muted);
    this.ctx = null;
    this.masterGain = null;
    this.musicGain = null;
    this.sfxGain = null;
    this.bgmTimer = null;
    this.bgmStepIndex = 0;
    this.noiseBufferCache = new Map();
  }

  ensureStarted() {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return false;
    if (!this.ctx) {
      this.ctx = new Ctx();
      this.masterGain = this.ctx.createGain();
      this.musicGain = this.ctx.createGain();
      this.sfxGain = this.ctx.createGain();
      this.musicGain.gain.value = 0.2;
      this.sfxGain.gain.value = 0.45;
      this.musicGain.connect(this.masterGain);
      this.sfxGain.connect(this.masterGain);
      this.masterGain.connect(this.ctx.destination);
      this._applyMuteState();
    }
    if (this.ctx.state === "suspended") {
      this.ctx.resume().catch(() => {});
    }
    return true;
  }

  setMuted(value) {
    this.muted = Boolean(value);
    this._applyMuteState();
    return this.muted;
  }

  toggleMuted() {
    return this.setMuted(!this.muted);
  }

  startBgm() {
    if (this.bgmTimer) return;
    if (!this.ensureStarted()) return;
    this._playBgmStep();
    this.bgmTimer = setInterval(() => this._playBgmStep(), 500);
  }

  stopBgm() {
    if (!this.bgmTimer) return;
    clearInterval(this.bgmTimer);
    this.bgmTimer = null;
  }

  onGameEnd(didWin) {
    this.stopBgm();
    if (didWin) this.playWin();
    else this.playGameOver();
  }

  playJump() {
    this._playTone({ freq: 420, duration: 0.11, gain: 0.2, type: "square" });
    this._playTone({ freq: 620, duration: 0.08, gain: 0.13, type: "triangle", when: 0.04 });
  }

  playEnemyDown() {
    this._playTone({ freq: 260, duration: 0.08, gain: 0.2, type: "square" });
    this._playTone({ freq: 180, duration: 0.12, gain: 0.16, type: "triangle", when: 0.02 });
  }

  playHit() {
    this._playNoise({ duration: 0.13, gain: 0.2 });
    this._playTone({ freq: 95, duration: 0.18, gain: 0.16, type: "sawtooth" });
  }

  playWin() {
    this._playTone({ freq: 392, duration: 0.14, gain: 0.2, type: "triangle" });
    this._playTone({ freq: 493.88, duration: 0.14, gain: 0.2, type: "triangle", when: 0.12 });
    this._playTone({ freq: 587.33, duration: 0.2, gain: 0.24, type: "triangle", when: 0.24 });
  }

  playGameOver() {
    this._playTone({ freq: 220, duration: 0.16, gain: 0.2, type: "sawtooth" });
    this._playTone({ freq: 164.81, duration: 0.2, gain: 0.2, type: "sawtooth", when: 0.12 });
    this._playTone({ freq: 130.81, duration: 0.24, gain: 0.2, type: "sawtooth", when: 0.24 });
  }

  _playBgmStep() {
    if (!this.ctx || this.muted) return;
    const note = BGM_PATTERN[this.bgmStepIndex % BGM_PATTERN.length];
    this.bgmStepIndex += 1;
    const powerFifth = note * 1.5;
    // Rock-like power chord pulse + bass hit
    this._playTone({ freq: note, duration: 0.34, gain: 0.14, type: "sawtooth", bus: "music" });
    this._playTone({ freq: powerFifth, duration: 0.28, gain: 0.1, type: "square", bus: "music", when: 0.01 });
    this._playTone({ freq: note / 2, duration: 0.2, gain: 0.13, type: "triangle", bus: "music", when: 0.02 });
    // Light kick/snare feel for momentum
    this._playTone({ freq: 62, duration: 0.08, gain: 0.12, type: "sine", bus: "music" });
    this._playNoise({ duration: 0.05, gain: 0.05, bus: "music", when: 0.24 });
  }

  _playTone({ freq, duration, gain, type = "sine", bus = "sfx", when = 0 }) {
    if (!this.ensureStarted()) return;
    if (this.muted) return;
    const targetBus = bus === "music" ? this.musicGain : this.sfxGain;
    const now = this.ctx.currentTime + when;
    const osc = this.ctx.createOscillator();
    const gainNode = this.ctx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, now);
    gainNode.gain.setValueAtTime(0.0001, now);
    gainNode.gain.exponentialRampToValueAtTime(Math.max(0.001, gain), now + 0.01);
    gainNode.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    osc.connect(gainNode);
    gainNode.connect(targetBus);
    osc.start(now);
    osc.stop(now + duration + 0.03);
  }

  _playNoise({ duration, gain, bus = "sfx", when = 0 }) {
    if (!this.ensureStarted()) return;
    if (this.muted) return;
    const bufferLength = Math.max(1, Math.floor(this.ctx.sampleRate * duration));
    const cacheKey = `${this.ctx.sampleRate}:${bufferLength}`;
    let buffer = this.noiseBufferCache.get(cacheKey);
    if (!buffer) {
      buffer = this.ctx.createBuffer(1, bufferLength, this.ctx.sampleRate);
      const channel = buffer.getChannelData(0);
      for (let i = 0; i < bufferLength; i += 1) {
        channel[i] = (Math.random() * 2 - 1) * (1 - i / bufferLength);
      }
      this.noiseBufferCache.set(cacheKey, buffer);
    }
    const source = this.ctx.createBufferSource();
    source.buffer = buffer;
    const gainNode = this.ctx.createGain();
    const now = this.ctx.currentTime + when;
    gainNode.gain.setValueAtTime(Math.max(0.001, gain), now);
    gainNode.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    source.connect(gainNode);
    gainNode.connect(bus === "music" ? this.musicGain : this.sfxGain);
    source.start(now);
    source.stop(now + duration + 0.03);
  }

  _applyMuteState() {
    if (!this.masterGain || !this.ctx) return;
    const now = this.ctx.currentTime;
    const target = this.muted ? 0.0001 : 1;
    this.masterGain.gain.cancelScheduledValues(now);
    this.masterGain.gain.setTargetAtTime(target, now, 0.02);
  }
}
