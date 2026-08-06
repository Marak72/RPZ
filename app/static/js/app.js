/* РПЗ ФСТЭК — интерфейсные помощники. Без внешних зависимостей. */
(function () {
  "use strict";

  /* --- Тема (светлая/тёмная), запоминается в браузере ------------------ */
  var THEME_KEY = "rpz-theme";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.querySelectorAll("[data-theme-icon]").forEach(function (el) {
      el.classList.toggle("hidden", el.dataset.themeIcon !== theme);
    });
  }

  applyTheme(localStorage.getItem(THEME_KEY) || "light");

  document.addEventListener("click", function (e) {
    var toggle = e.target.closest("[data-theme-toggle]");
    if (!toggle) return;
    var next =
      document.documentElement.getAttribute("data-theme") === "dark"
        ? "light"
        : "dark";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
  });

  /* --- Боковая панель на узких экранах --------------------------------- */
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-sidebar-toggle]")) {
      document.querySelector(".sidebar").classList.toggle("is-open");
    }
  });

  /* --- Закрытие сообщений ---------------------------------------------- */
  document.addEventListener("click", function (e) {
    var close = e.target.closest("[data-dismiss]");
    if (close) close.closest(".alert").remove();
  });

  /* --- Вкладки ---------------------------------------------------------- */
  document.addEventListener("click", function (e) {
    var tab = e.target.closest("[data-tab]");
    if (!tab) return;
    e.preventDefault();
    var group = tab.closest("[data-tabs]");
    group.querySelectorAll("[data-tab]").forEach(function (t) {
      t.classList.toggle("is-active", t === tab);
    });
    var scope = group.parentElement;
    scope.querySelectorAll("[data-tab-panel]").forEach(function (panel) {
      panel.classList.toggle("is-active", panel.dataset.tabPanel === tab.dataset.tab);
    });
  });

  /* --- Живой фильтр таблицы -------------------------------------------- */
  function filterTable(input) {
    var table = document.getElementById(input.dataset.filter);
    if (!table) return;
    var q = input.value.trim().toLowerCase();
    var shown = 0;
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      if (tr.dataset.empty !== undefined) return;
      var hit = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
      tr.classList.toggle("hidden", !hit);
      if (hit) shown++;
    });
    var counter = document.querySelector('[data-filter-count="' + input.dataset.filter + '"]');
    if (counter) counter.textContent = shown;
  }

  document.addEventListener("input", function (e) {
    if (e.target.dataset && e.target.dataset.filter) filterTable(e.target);
  });

  /* --- «/» фокусирует поиск -------------------------------------------- */
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) {
      var box = document.querySelector("[data-filter], [data-search-focus]");
      if (box) {
        e.preventDefault();
        box.focus();
      }
    }
    if (e.key === "Escape") closeModal();
  });

  /* --- Массовое выделение ---------------------------------------------- */
  function updateSelectionCount(scopeSel) {
    var scope = document.querySelector(scopeSel) || document;
    var boxes = scope.querySelectorAll('input[type="checkbox"][data-select]:not(:disabled)');
    var checked = 0;
    boxes.forEach(function (b) {
      if (b.checked) checked++;
      var tr = b.closest("tr");
      if (tr) tr.classList.toggle("is-selected", b.checked);
    });
    document.querySelectorAll("[data-selected-count]").forEach(function (el) {
      if (!el.dataset.selectedCount || scopeSel.indexOf(el.dataset.selectedCount) !== -1) {
        el.textContent = checked;
      }
    });
    return checked;
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-select-all]");
    if (!btn) return;
    e.preventDefault();
    var group = btn.dataset.selectAll;
    var mode = btn.dataset.selectMode || "all";
    document
      .querySelectorAll('input[type="checkbox"][data-select="' + group + '"]')
      .forEach(function (box) {
        if (box.disabled) return;
        if (mode === "none") box.checked = false;
        else if (mode === "pending") box.checked = box.dataset.pending === "1";
        else box.checked = true;
      });
    updateSelectionCount("[data-select-scope]");
  });

  document.addEventListener("change", function (e) {
    if (e.target.dataset && e.target.dataset.select !== undefined) {
      updateSelectionCount("[data-select-scope]");
    }
  });

  /* --- Копирование в буфер --------------------------------------------- */
  function copyText(text, btn) {
    var done = function () {
      if (!btn) return;
      btn.classList.add("is-copied");
      setTimeout(function () { btn.classList.remove("is-copied"); }, 1200);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done);
    } else {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (err) { /* noop */ }
      document.body.removeChild(ta);
    }
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (btn) {
      e.preventDefault();
      copyText(btn.dataset.copy, btn);
      return;
    }
    // Скопировать все видимые значения колонки
    var all = e.target.closest("[data-copy-column]");
    if (all) {
      e.preventDefault();
      var table = document.getElementById(all.dataset.copyColumn);
      if (!table) return;
      var values = [];
      table.querySelectorAll("tbody tr").forEach(function (tr) {
        if (tr.classList.contains("hidden") || tr.dataset.empty !== undefined) return;
        var cell = tr.querySelector("[data-value]");
        if (cell) values.push(cell.dataset.value);
      });
      copyText(values.join("\n"), all);
      var label = all.querySelector("[data-copy-label]");
      if (label) {
        var old = label.textContent;
        label.textContent = "Скопировано: " + values.length;
        setTimeout(function () { label.textContent = old; }, 1500);
      }
    }
  });

  /* --- Подтверждение опасных действий ---------------------------------- */
  var pendingForm = null;

  function openModal(opts) {
    var backdrop = document.getElementById("confirmModal");
    if (!backdrop) return false;
    backdrop.querySelector("[data-modal-title]").textContent = opts.title;
    backdrop.querySelector("[data-modal-body]").innerHTML = opts.body;
    var ok = backdrop.querySelector("[data-modal-ok]");
    ok.textContent = opts.okText || "Подтвердить";
    ok.className = "btn " + (opts.okClass || "btn--danger");
    backdrop.classList.add("is-open");
    return true;
  }

  function closeModal() {
    var backdrop = document.getElementById("confirmModal");
    if (backdrop) backdrop.classList.remove("is-open");
    pendingForm = null;
  }

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-modal-cancel]") || e.target.id === "confirmModal") {
      closeModal();
      return;
    }
    if (e.target.closest("[data-modal-ok]")) {
      var form = pendingForm;
      closeModal();
      if (form) {
        form.dataset.confirmed = "1";
        if (form.__submitter) form.__submitter.click();
        else form.submit();
      }
    }
  });

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form.dataset.confirm || form.dataset.confirmed === "1") return;
    // Безопасные действия (предпросмотр) подтверждения не требуют.
    if (e.submitter && e.submitter.hasAttribute("data-no-confirm")) return;
    var count = form.querySelectorAll(
      'input[type="checkbox"][data-select]:checked'
    ).length;
    if (form.dataset.confirmRequiresSelection && count === 0) return; // пусть обработает сервер
    e.preventDefault();
    pendingForm = form;
    form.__submitter = e.submitter;
    var body = form.dataset.confirmBody || "";
    if (count) {
      body = body.replace("{n}", count);
    }
    if (!openModal({
      title: form.dataset.confirmTitle || "Подтвердите действие",
      body: body,
      okText: form.dataset.confirmOk || "Подтвердить",
    })) {
      form.dataset.confirmed = "1";
      form.submit();
    }
  });

  /* --- Относительное время --------------------------------------------- */
  document.querySelectorAll("[data-since]").forEach(function (el) {
    var ts = parseInt(el.dataset.since, 10);
    if (!ts) return;
    var mins = Math.floor((Date.now() / 1000 - ts) / 60);
    var text;
    if (mins < 1) text = "только что";
    else if (mins < 60) text = mins + " мин назад";
    else if (mins < 1440) text = Math.floor(mins / 60) + " ч назад";
    else text = Math.floor(mins / 1440) + " дн назад";
    el.textContent = text;
  });

  /* Первичный подсчёт выделения */
  updateSelectionCount("[data-select-scope]");
})();
