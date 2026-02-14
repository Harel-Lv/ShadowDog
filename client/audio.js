const BGM_PATTERN = [110, 123.47, 146.83, 164.81, 146.83, 123.47];

export class GameAudio {
  constructor({ muted = false } = {}) {
    this.muted = Boolean(muted);
    this.ctx = null;
    this.masterGain = null;
    this.musicGain = null;
    this.sfxGain = null;
    this.bgmTimer = null;
    this.bgmStepIndex = 0;
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
    this.bgmTimer = setInterval(() => this._playBgmStep(), 1000);
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
    this._playTone({ freq: note, duration: 0.5, gain: 0.12, type: "sawtooth", bus: "music" });
    this._playTone({ freq: note * 2, duration: 0.15, gain: 0.07, type: "triangle", bus: "music", when: 0.08 });
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

  _playNoise({ duration, gain }) {
    if (!this.ensureStarted()) return;
    if (this.muted) return;
    const bufferLength = Math.max(1, Math.floor(this.ctx.sampleRate * duration));
    const buffer = this.ctx.createBuffer(1, bufferLength, this.ctx.sampleRate);
    const channel = buffer.getChannelData(0);
    for (let i = 0; i < bufferLength; i += 1) {
      channel[i] = (Math.random() * 2 - 1) * (1 - i / bufferLength);
    }
    const source = this.ctx.createBufferSource();
    source.buffer = buffer;
    const gainNode = this.ctx.createGain();
    const now = this.ctx.currentTime;
    gainNode.gain.setValueAtTime(Math.max(0.001, gain), now);
    gainNode.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    source.connect(gainNode);
    gainNode.connect(this.sfxGain);
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
