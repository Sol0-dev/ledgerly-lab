/* Ledgerly capture effects: confetti + a capture sound.
   The app polls /api/flags/new; each newly captured flag triggers a burst.
   Slot numbers only - the capture never reveals which class it belongs to. */

(function () {
  "use strict";

  if (window.LedgerlyFX) return;

  var hue = Number(document.body.dataset.hue || 218);

  /* ---------------- canvas confetti ---------------- */

  var canvas = document.createElement("canvas");
  canvas.id = "fx-canvas";
  document.body.appendChild(canvas);
  var ctx2d = canvas.getContext("2d");
  var W = 0, H = 0, dpr = 1;
  var parts = [];
  var running = false;

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx2d.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  window.addEventListener("resize", resize);
  resize();

  function burst(count, hueOffset) {
    var base = hue + (hueOffset || 0);
    for (var i = 0; i < (count || 120); i++) {
      parts.push({
        x: W * (0.3 + Math.random() * 0.4),
        y: -20 - Math.random() * H * 0.3,
        vx: (Math.random() - 0.5) * 7,
        vy: 3 + Math.random() * 6,
        r: 4 + Math.random() * 5,
        rot: Math.random() * Math.PI,
        vr: (Math.random() - 0.5) * 0.3,
        color: "hsl(" + (base + Math.floor(Math.random() * 40) - 20) + " 70% 55%)",
        life: 1
      });
    }
    if (!running) { running = true; requestAnimationFrame(step); }
  }

  function step() {
    ctx2d.clearRect(0, 0, W, H);
    var alive = [];
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      p.x += p.vx; p.y += p.vy;
      p.vy += 0.12;
      p.rot += p.vr;
      p.life -= 0.004;
      if (p.y > H + 40 || p.life <= 0) continue;
      ctx2d.save();
      ctx2d.translate(p.x, p.y);
      ctx2d.rotate(p.rot);
      ctx2d.globalAlpha = Math.max(0, Math.min(1, p.life));
      ctx2d.fillStyle = p.color;
      ctx2d.fillRect(-p.r / 2, -p.r / 2, p.r, p.r * 0.66);
      ctx2d.restore();
      alive.push(p);
    }
    parts = alive;
    if (parts.length) { requestAnimationFrame(step); } else { running = false; ctx2d.clearRect(0, 0, W, H); }
  }

  /* ---------------- per-class sounds ---------------- */

  var AC = null;
  function audio() {
    if (!AC) AC = new (window.AudioContext || window.webkitAudioContext)();
    if (AC.state === "suspended") AC.resume();
    return AC;
  }

  function note(freq, start, dur, type, vol) {
    var ac = audio();
    var o = ac.createOscillator();
    var g = ac.createGain();
    o.type = type || "sine";
    o.frequency.setValueAtTime(freq, ac.currentTime + start);
    g.gain.setValueAtTime(0.0001, ac.currentTime + start);
    g.gain.exponentialRampToValueAtTime(vol || 0.18, ac.currentTime + start + 0.015);
    g.gain.exponentialRampToValueAtTime(0.0001, ac.currentTime + start + dur);
    o.connect(g); g.connect(ac.destination);
    o.start(ac.currentTime + start);
    o.stop(ac.currentTime + start + dur + 0.05);
  }

  function captureRiff() {
    note(660, 0, 0.2, "triangle");
    note(880, 0.14, 0.2, "triangle");
    note(1320, 0.28, 0.45, "triangle");
  }

  /* ---------------- capture polling ---------------- */

  var seen = {};
  var ON_COMPLETE = window.LedgerlyOnComplete || null;

  function poll() {
    fetch("/api/flags/new", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var caps = data.captures || [];
        for (var i = 0; i < caps.length; i++) {
          var c = caps[i];
          if (seen["s" + c.slot]) continue;
          seen["s" + c.slot] = 1;
          captureRiff();
          burst(90, 15);
        }
        if (caps.length && ON_COMPLETE) ON_COMPLETE(caps.length);
      })
      .catch(function () { });
  }

  setInterval(poll, 5000);
  poll();

  window.LedgerlyFX = { burst: burst, audio: audio };
})();
