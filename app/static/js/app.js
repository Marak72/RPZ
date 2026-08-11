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
        else if (mode === "inzone") box.checked = box.dataset.inzone === "1";
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

  /* --- Доска задач: быстрое добавление ---------------------------------- */
  document.addEventListener("click", function (e) {
    var open = e.target.closest("[data-quick-open]");
    if (open) {
      var box = open.parentNode.querySelector("[data-quick-form]");
      if (!box) return;
      box.classList.remove("hidden");
      open.classList.add("hidden");
      var field = box.querySelector('input[name="title"]');
      if (field) field.focus();
      return;
    }
    var cancel = e.target.closest("[data-quick-cancel]");
    if (cancel) {
      var form = cancel.closest("[data-quick-form]");
      form.classList.add("hidden");
      var btn = form.parentNode.querySelector("[data-quick-open]");
      if (btn) btn.classList.remove("hidden");
    }
  });

  /* --- Доска задач: перетаскивание карточек ------------------------------ */
  var dragged = null;

  document.addEventListener("dragstart", function (e) {
    var card = e.target.closest("[data-task]");
    if (!card) return;
    dragged = card;
    card.classList.add("is-dragging");
    e.dataTransfer.effectAllowed = "move";
    // Firefox начинает перетаскивание, только если что-то положить в данные.
    e.dataTransfer.setData("text/plain", card.dataset.task);
  });

  document.addEventListener("dragend", function () {
    if (dragged) dragged.classList.remove("is-dragging");
    document.querySelectorAll("[data-drop]").forEach(function (zone) {
      zone.classList.remove("is-over");
    });
    dragged = null;
  });

  document.addEventListener("dragover", function (e) {
    var zone = e.target.closest("[data-drop]");
    if (!zone || !dragged) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    zone.classList.add("is-over");
  });

  document.addEventListener("dragleave", function (e) {
    var zone = e.target.closest("[data-drop]");
    if (zone && !zone.contains(e.relatedTarget)) zone.classList.remove("is-over");
  });

  document.addEventListener("drop", function (e) {
    var zone = e.target.closest("[data-drop]");
    if (!zone || !dragged) return;
    e.preventDefault();
    zone.classList.remove("is-over");

    var column = zone.closest("[data-status]");
    var form = document.getElementById("moveForm");
    // Адрес переноса берём с карточки: собирать его из шаблона строкой —
    // верный способ промахнуться мимо маршрута.
    var moveUrl = dragged.dataset.moveUrl;
    if (!column || !form || !moveUrl) return;

    // Карточку переносим сразу: ждать перезагрузку страницы неприятно.
    var note = zone.querySelector("[data-empty-note]");
    if (note) note.remove();
    zone.appendChild(dragged);
    refreshColumnCounts();

    form.action = moveUrl;
    form.querySelector("[data-move-status]").value = column.dataset.status;
    form.submit();
  });

  function refreshColumnCounts() {
    document.querySelectorAll("[data-status]").forEach(function (column) {
      var counter = column.querySelector("[data-col-count]");
      if (counter) counter.textContent = column.querySelectorAll("[data-task]").length;
    });
  }

  /* Первичный подсчёт выделения */
  updateSelectionCount("[data-select-scope]");

  /* --- Плашка фоновых заданий ------------------------------------------
     Поиск хостов в SIEM идёт минутами. Раньше страница просто висела на
     кнопке; теперь работа уходит в фон, а здесь показывается её ход.
     Опрос лёгкий (короткий JSON) и разрежается, как только активных
     заданий не остаётся, — постоянной нагрузки на сервер не создаёт. */
  var tray = document.querySelector("[data-jobs-tray]");
  var jobsUrl = meta("jobs-url");

  if (tray && jobsUrl) {
    var ACTIVE_INTERVAL = 2000;   // пока работа идёт — следим часто
    var IDLE_INTERVAL = 30000;    // иначе просто проверяем, не начал ли кто
    var timer = null;
    var lastSignature = "";

    var pollJobs = function (delay) {
      clearTimeout(timer);
      timer = setTimeout(fetchJobs, delay);
    };

    var fetchJobs = function () {
      fetch(jobsUrl, { headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : { jobs: [] }; })
        .then(function (data) {
          var jobs = data.jobs || [];
          render(jobs);
          var busy = jobs.some(function (j) { return j.active; });
          pollJobs(busy ? ACTIVE_INTERVAL : IDLE_INTERVAL);
        })
        .catch(function () {
          // Сеть моргнула — не шумим, просто попробуем позже.
          pollJobs(IDLE_INTERVAL);
        });
    };

    var render = function (jobs) {
      // Перерисовываем, только когда что-то изменилось: иначе плашка
      // мигала бы каждые две секунды.
      var signature = jobs.map(function (j) {
        return [j.id, j.status, j.processed, j.found, j.detail].join(":");
      }).join("|");
      if (signature === lastSignature) return;
      lastSignature = signature;

      tray.textContent = "";
      jobs.forEach(function (job) { tray.appendChild(buildCard(job)); });
    };

    var buildCard = function (job) {
      var tpl = document.getElementById("jobCardTemplate");
      var card = tpl.content.firstElementChild.cloneNode(true);
      card.classList.add("job--" + job.status);

      card.querySelector("[data-job-title]").textContent = job.title;
      card.querySelector("[data-job-spinner]").classList.toggle(
        "hidden", !job.active
      );

      var detail = card.querySelector("[data-job-detail]");
      detail.textContent = job.active
        ? (job.detail || "Запускается…")
        : job.message;

      var bar = card.querySelector("[data-job-bar]");
      bar.style.width = (job.active ? job.percent : 100) + "%";

      // Неудачи показываем рядом с находками: без этого «найдено 0» не
      // отличить от «все запросы упали», а это разные ситуации.
      var counter = card.querySelector("[data-job-counter]");
      var tail = " · найдено " + job.found
        + (job.failed ? " · ошибок " + job.failed : "");
      if (job.active) {
        counter.textContent = job.total
          ? job.processed + " из " + job.total + tail
          : "выполняется";
      } else {
        counter.textContent = job.status_title;
      }
      if (job.failed) card.classList.add("job--has-errors");

      // Закрыть можно только завершённое: спрятать идущую работу — значит
      // потерять её из виду и решить, что ничего не запускалось.
      var close = card.querySelector("[data-job-close]");
      close.classList.toggle("hidden", job.active);
      close.addEventListener("click", function () {
        card.remove();
        lastSignature = "";
        post(jobsUrl.replace(/status\.json$/, job.id + "/dismiss"));
      });

      var link = card.querySelector("[data-job-link]");
      if (!job.active && job.url) {
        link.href = job.url;
        link.classList.remove("hidden");
      }
      return card;
    };

    var post = function (url) {
      fetch(url, {
        method: "POST",
        headers: { "X-CSRFToken": meta("csrf-token") },
      }).catch(function () { /* плашку уже убрали, ответ не важен */ });
    };

    fetchJobs();
  }

  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute("content") : "";
  }
})();
