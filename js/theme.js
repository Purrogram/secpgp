/* 种子 → M3 色板 → CSS 变量；在样式表之前执行，避免闪回 */
(function () {
  "use strict";

  /* 生成器加载失败时保留 styles.css 里的静态兜底值 */
  if (!window.MCU) return;

  var STORE_KEY = "pgp_theme_seed_v1";
  var MODE_KEY = "pgp_theme_mode_v1";
  var CUSTOM_KEY = "pgp_theme_custom_v1";
  var DEFAULT_SEED = "#0061a4";

  var root = document.documentElement;
  var schemes = null;
  var currentSeed = DEFAULT_SEED;
  var currentSource = "default";
  var subscribers = [];
  /* localStorage 不可用（部分 file:// 环境）时的会话内兜底 */
  var memSeed = null;
  var memMode = "auto";
  var memCustom = null;

  /* ── 颜色工具 ── */
  function normHex(v) {
    if (!v) return null;
    v = String(v).trim();
    if (/^#[0-9a-f]{6}$/i.test(v)) return v.toLowerCase();
    if (/^#[0-9a-f]{3}$/i.test(v)) return ("#" + v[1] + v[1] + v[2] + v[2] + v[3] + v[3]).toLowerCase();
    if (/^[0-9a-f]{6}$/i.test(v)) return ("#" + v).toLowerCase();
    return null;
  }

  /* ── 种子 / 模式 ── */  function storedSeed() {
    try { return normHex(localStorage.getItem(STORE_KEY)) || memSeed; } catch (e) { return memSeed; }
  }

  function storedMode() {
    try {
      var m = localStorage.getItem(MODE_KEY);
      if (m === "light" || m === "dark" || m === "auto") return m;
      return memMode;
    } catch (e) { return memMode; }
  }

  function effectiveDark() {
    var m = storedMode();
    if (m === "light") return false;
    if (m === "dark") return true;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function resolveSeed() {
    var manual = storedSeed();
    if (manual) return { seed: manual, source: "manual" };
    return { seed: DEFAULT_SEED, source: "default" };
  }

  function storedCustom() {
    if (memCustom) return memCustom.slice();
    try {
      var raw = JSON.parse(localStorage.getItem(CUSTOM_KEY) || "[]");
      if (!Array.isArray(raw)) return [];
      var out = [];
      for (var i = 0; i < raw.length; i++) {
        var v = normHex(raw[i]);
        if (v && out.indexOf(v) < 0) out.push(v);
      }
      return out;
    } catch (e) { return []; }
  }

  /* ── M3 角色 ── */
  var ROLES = [
    ["primary", "--md-primary"],
    ["onPrimary", "--md-on-primary"],
    ["primaryContainer", "--md-primary-container"],
    ["onPrimaryContainer", "--md-on-primary-container"],
    ["secondaryContainer", "--md-secondary-container"],
    ["onSecondaryContainer", "--md-on-secondary-container"],
    ["tertiary", "--md-tertiary"],
    ["onTertiary", "--md-on-tertiary"],
    ["tertiaryContainer", "--md-tertiary-container"],
    ["onTertiaryContainer", "--md-on-tertiary-container"],
    ["error", "--md-error"],
    ["onError", "--md-on-error"],
    ["errorContainer", "--md-error-container"],
    ["onErrorContainer", "--md-on-error-container"],
    ["background", "--md-background"],
    ["surface", "--md-surface"],
    ["surfaceContainerLowest", "--md-surface-container-lowest"],
    ["surfaceContainerLow", "--md-surface-container-low"],
    ["surfaceContainer", "--md-surface-container"],
    ["surfaceContainerHigh", "--md-surface-container-high"],
    ["surfaceContainerHighest", "--md-surface-container-highest"],
    ["onSurface", "--md-on-surface"],
    ["onSurfaceVariant", "--md-on-surface-variant"],
    ["outline", "--md-outline"],
    ["outlineVariant", "--md-outline-variant"],
    ["inverseSurface", "--md-inverse-surface"],
    ["inverseOnSurface", "--md-inverse-on-surface"]
  ];

  /* 不随种子变化的静态值；强制模式时须显式覆盖 */
  var STATIC_LIGHT = {
    "--md-success": "#1F6B48",
    "--md-on-success": "#FFFFFF",
    "--md-success-container": "#A5F2CD",
    "--md-on-success-container": "#00210F",
    "--md-warn": "#7A5900",
    "--md-on-warn": "#FFFFFF",
    "--md-warn-container": "#FFE08A",
    "--md-on-warn-container": "#261A00",
    "--scrim": "rgba(0, 0, 0, 0.32)",
    "--md-elevation-1": "0 1px 2px rgba(0, 0, 0, 0.10), 0 1px 3px 1px rgba(0, 0, 0, 0.06)",
    "--md-elevation-2": "0 1px 2px rgba(0, 0, 0, 0.10), 0 2px 6px 2px rgba(0, 0, 0, 0.08)",
    "--md-elevation-3": "0 2px 3px rgba(0, 0, 0, 0.10), 0 4px 8px 3px rgba(0, 0, 0, 0.10)",
    "--seg-track": "var(--md-surface-container-highest)",
    "--seg-pill": "var(--md-surface-container-lowest)",
    "--seg-on-pill": "var(--md-on-surface)"
  };

  var STATIC_DARK = {
    "--md-success": "#7BDCB5",
    "--md-on-success": "#00391F",
    "--md-success-container": "#00522E",
    "--md-on-success-container": "#A5F2CD",
    "--md-warn": "#FFD77A",
    "--md-on-warn": "#3F2E00",
    "--md-warn-container": "#5C4400",
    "--md-on-warn-container": "#FFE08A",
    "--scrim": "rgba(0, 0, 0, 0.4)",
    "--md-elevation-1": "0 1px 2px rgba(0, 0, 0, 0.3), 0 1px 3px 1px rgba(0, 0, 0, 0.15)",
    "--md-elevation-2": "0 1px 2px rgba(0, 0, 0, 0.3), 0 2px 6px 2px rgba(0, 0, 0, 0.15)",
    "--md-elevation-3": "0 1px 3px rgba(0, 0, 0, 0.3), 0 4px 8px 3px rgba(0, 0, 0, 0.15)",
    "--seg-track": "var(--md-surface-container-high)",
    "--seg-pill": "var(--md-secondary-container)",
    "--seg-on-pill": "var(--md-on-secondary-container)"
  };

  function setVar(name, argb) {
    root.style.setProperty(name, MCU.hexFromArgb(argb));
  }

  function selectArrow(hex) {
    var svg = "<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'>" +
      "<path d='M1 1l4 4 4-4' fill='none' stroke='" + hex + "' stroke-width='1.6' " +
      "stroke-linecap='round' stroke-linejoin='round'/></svg>";
    root.style.setProperty("--select-arrow", "url(\"data:image/svg+xml," + encodeURIComponent(svg) + "\")");
  }

  function favicon(hex) {
    var path = "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z";
    var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path fill='" + hex + "' d='" + path + "'/></svg>";
    var link = document.querySelector('link[rel="icon"]');
    if (link) link.setAttribute("href", "data:image/svg+xml," + encodeURIComponent(svg));
  }

  /* 两个 meta 都写当前表面色，强制模式才不会错 */
  function metaTheme(surfaceHex) {
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) metas[i].setAttribute("content", surfaceHex);
  }

  function apply() {
    if (!schemes) return;
    var dark = effectiveDark();
    var s = dark ? schemes.dark : schemes.light;
    var C = MCU.MaterialDynamicColors;

    root.style.colorScheme = dark ? "dark" : "light";

    for (var i = 0; i < ROLES.length; i++) {
      setVar(ROLES[i][1], s.getArgb(C[ROLES[i][0]]));
    }

    var stat = dark ? STATIC_DARK : STATIC_LIGHT;
    for (var k in stat) {
      if (Object.prototype.hasOwnProperty.call(stat, k)) root.style.setProperty(k, stat[k]);
    }

    setVar("--md-primary-hover", s.primaryPalette.tone(dark ? 85 : 35));
    setVar("--danger-hover", s.errorPalette.tone(dark ? 85 : 35));
    setVar("--danger-container-hover", s.errorPalette.tone(dark ? 35 : 85));

    selectArrow(MCU.hexFromArgb(s.getArgb(C.outline)));
    favicon(MCU.hexFromArgb(s.getArgb(C.primary)));
    metaTheme(MCU.hexFromArgb(s.getArgb(C.surface)));

    for (var j = 0; j < subscribers.length; j++) subscribers[j](currentSeed, currentSource, dark);
  }

  function rebuild() {
    var r = resolveSeed();
    currentSeed = r.seed;
    currentSource = r.source;
    try {
      var hct = MCU.Hct.fromInt(MCU.argbFromHex(r.seed));
      schemes = {
        light: new MCU.SchemeTonalSpot(hct, false, 0),
        dark: new MCU.SchemeTonalSpot(hct, true, 0)
      };
    } catch (e) {
      currentSeed = DEFAULT_SEED;
      currentSource = "default";
      var d = MCU.Hct.fromInt(MCU.argbFromHex(DEFAULT_SEED));
      schemes = {
        light: new MCU.SchemeTonalSpot(d, false, 0),
        dark: new MCU.SchemeTonalSpot(d, true, 0)
      };
    }
    apply();
  }

  /* ── 对外 API ── */
  window.Theme = {
    getSeed: function () { return currentSeed; },
    getSource: function () { return currentSource; },
    getMode: storedMode,
    setSeed: function (hex) {
      var v = normHex(hex);
      if (!v) return false;
      memSeed = v;
      try { localStorage.setItem(STORE_KEY, v); } catch (e) { /* 受限环境：本次会话有效 */ }
      rebuild();
      return true;
    },
    setMode: function (mode) {
      var m = mode === "light" || mode === "dark" ? mode : "auto";
      memMode = m;
      try { localStorage.setItem(MODE_KEY, m); } catch (e) { /* ignore */ }
      apply();
    },
    onChange: function (fn) { if (typeof fn === "function") subscribers.push(fn); },
    refresh: apply
  };

  /* ── 启动 ── */
  rebuild();

  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  function onSystemChange() {
    if (storedMode() === "auto") apply();
  }
  if (mq.addEventListener) mq.addEventListener("change", onSystemChange);
  else if (mq.addListener) mq.addListener(onSystemChange);

  /* ── 面板 ── */
  function initUI() {
    var btn = document.getElementById("themeBtn");
    var modal = document.getElementById("themeModal");
    if (!btn || !modal) return;

    var modeBox = document.getElementById("themeMode");
    var modeButtons = modeBox ? modeBox.querySelectorAll(".mode-tab") : [];
    var indicator = modeBox ? modeBox.querySelector(".mode-indicator") : null;
    var seedGrid = document.getElementById("seedGrid");
    var customBtn = document.getElementById("themeCustom");
    var saveBtn = document.getElementById("themeSave");
    var colorInput = document.getElementById("themeColor");
    var customSeeds = storedCustom();

    function allDots() {
      return seedGrid ? seedGrid.querySelectorAll(".seed-dot") : [];
    }

    function isSaved(hex) {
      if (!hex) return true;
      if (customSeeds.indexOf(hex) >= 0) return true;
      var presets = seedGrid ? seedGrid.querySelectorAll(".seed-dot:not(.custom)") : [];
      for (var i = 0; i < presets.length; i++) {
        if ((presets[i].getAttribute("data-seed") || "").toLowerCase() === hex) return true;
      }
      return false;
    }

    function syncSave() {
      if (!saveBtn || !colorInput) return;
      var v = normHex(colorInput.value);
      saveBtn.disabled = !v || isSaved(v);
    }

    function paintSeed() {
      var dots = allDots();
      for (var i = 0; i < dots.length; i++) {
        var on = (dots[i].getAttribute("data-seed") || "").toLowerCase() === currentSeed;
        dots[i].classList.toggle("active", on);
        dots[i].setAttribute("aria-pressed", on ? "true" : "false");
      }
      if (colorInput) colorInput.value = currentSeed;
      syncSave();
    }

    function renderCustom() {
      if (!seedGrid) return;
      var old = seedGrid.querySelectorAll(".seed-dot.custom");
      for (var i = 0; i < old.length; i++) old[i].remove();
      for (var j = 0; j < customSeeds.length; j++) {
        var hex = customSeeds[j];
        var b = document.createElement("button");
        b.type = "button";
        b.className = "seed-dot custom";
        b.setAttribute("data-seed", hex);
        b.style.setProperty("--dot", hex);
        b.setAttribute("aria-label", "自定义 " + hex);
        b.title = hex;
        seedGrid.appendChild(b);
      }
      paintSeed();
    }

    function saveCustom() {
      var hex = normHex(colorInput.value);
      if (!hex) return;
      if (!isSaved(hex)) {
        customSeeds.push(hex);
        memCustom = customSeeds.slice();
        try { localStorage.setItem(CUSTOM_KEY, JSON.stringify(customSeeds)); } catch (e) { /* ignore */ }
        renderCustom();
      }
      window.Theme.setSeed(hex);
    }

    function positionIndicator(active, animate) {
      if (!indicator || !active || !active.offsetWidth) return;
      if (!animate) indicator.classList.add("settled");
      indicator.style.width = active.offsetWidth + "px";
      indicator.style.transform = "translateX(" + active.offsetLeft + "px)";
      if (!animate) {
        void indicator.offsetWidth;
        indicator.classList.remove("settled");
      }
    }

    function paintMode(animate) {
      var mode = storedMode();
      var active = null;
      for (var i = 0; i < modeButtons.length; i++) {
        var on = modeButtons[i].getAttribute("data-mode") === mode;
        modeButtons[i].classList.toggle("active", on);
        modeButtons[i].setAttribute("aria-pressed", on ? "true" : "false");
        if (on) active = modeButtons[i];
      }
      positionIndicator(active, animate);
    }

    btn.addEventListener("click", function () {
      modal.classList.add("open");
      paintSeed();
      paintMode(false);
      /* 焦点移进弹窗，Escape 才能从弹窗冒泡到 app.js 的关闭逻辑 */
      var box = modal.querySelector(".modal");
      if (box && box.focus) box.focus();
    });

    modal.querySelectorAll("[data-close]").forEach(function (el) {
      el.addEventListener("click", function () { modal.classList.remove("open"); });
    });

    for (var i = 0; i < modeButtons.length; i++) {
      modeButtons[i].addEventListener("click", function () {
        window.Theme.setMode(this.getAttribute("data-mode"));
      });
    }

    /* 事件委托：保存后追加的自定义色圆点不需要单独绑定 */
    if (seedGrid) {
      seedGrid.addEventListener("click", function (e) {
        var dot = e.target.closest ? e.target.closest(".seed-dot") : null;
        if (dot && seedGrid.contains(dot)) window.Theme.setSeed(dot.getAttribute("data-seed"));
      });
    }

    if (customBtn && colorInput) {
      customBtn.addEventListener("click", function () { colorInput.click(); });
      colorInput.addEventListener("input", function () {
        window.Theme.setSeed(colorInput.value);
      });
    }
    if (saveBtn) saveBtn.addEventListener("click", saveCustom);

    window.addEventListener("resize", function () {
      if (modal.classList.contains("open")) paintMode(false);
    });

    window.Theme.onChange(function () {
      paintSeed();
      paintMode(true);
    });

    renderCustom();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initUI);
  } else {
    initUI();
  }
})();
