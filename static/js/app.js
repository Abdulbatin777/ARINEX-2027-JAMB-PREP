document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.querySelector(".nav-links");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const opened = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(opened));
    });
  }

  document.querySelectorAll("[data-confirm]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (!window.confirm(button.dataset.confirm || "Are you sure?")) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent.trim());
        const old = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => button.textContent = old, 1500);
      } catch (_) {
        window.prompt("Copy this value:", target.textContent.trim());
      }
    });
  });

  const mockForm = document.getElementById("mock-subject-form");
  if (mockForm) {
    mockForm.addEventListener("submit", (event) => {
      const checked = mockForm.querySelectorAll('input[name="subject_ids"]:checked');
      if (checked.length !== 3) {
        event.preventDefault();
        alert("Choose exactly three subjects besides Use of English.");
      }
    });
  }

  const answerForm = document.getElementById("answer-form");
  const actionInput = answerForm && answerForm.querySelector('input[name="action"]');
  const nextInput = answerForm && answerForm.querySelector('input[name="next_q"]');
  document.querySelectorAll(".question-number").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (!answerForm || !nextInput) return;
      event.preventDefault();
      const match = link.href.match(/[?&]q=(\d+)/);
      if (match) nextInput.value = match[1];
      if (actionInput) actionInput.value = "save";
      answerForm.submit();
    });
  });

  const submitForm = document.getElementById("submit-exam-form");
  if (submitForm && answerForm) {
    submitForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (actionInput) actionInput.value = "submit";
      answerForm.submit();
    });
  }

  const timer = document.getElementById("exam-timer");
  if (timer && answerForm) {
    let seconds = Math.max(0, Number.parseInt(timer.dataset.seconds || "0", 10));
    const format = (value) => {
      const h = Math.floor(value / 3600);
      const m = Math.floor((value % 3600) / 60);
      const s = value % 60;
      return [h, m, s].map((n) => String(n).padStart(2, "0")).join(":");
    };
    timer.textContent = format(seconds);
    const tick = () => {
      timer.textContent = format(seconds);
      if (seconds <= 0) {
        if (actionInput) actionInput.value = "submit";
        answerForm.submit();
        return;
      }
      seconds -= 1;
      window.setTimeout(tick, 1000);
    };
    window.setTimeout(tick, 1000);
  }

  if ("serviceWorker" in navigator && window.location.protocol.startsWith("http")) {
    navigator.serviceWorker.register("/static/sw.js").catch(() => {});
  }
    // AJAX: Publish or unpublish a question without reloading the page
  document.querySelectorAll(".toggle-publish-button").forEach((button) => {
    button.addEventListener("click", async () => {
      const originalText = button.textContent.trim();
      const wasPublished = button.dataset.published === "true";
      const csrfToken = document.querySelector(
        'input[name="csrf_token"]'
      )?.value;

      if (!csrfToken) {
        alert("Security token not found. Please refresh the page.");
        return;
      }

      button.disabled = true;
      button.textContent = "Saving...";

      try {
        const response = await fetch(button.dataset.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify({})
        });

        const data = await response.json();

        if (!response.ok || !data.ok) {
          throw new Error(data.message || "Could not update the question.");
        }

        button.dataset.published = String(data.is_published);
        button.textContent = data.is_published ? "Unpublish" : "Publish";

        const row = button.closest("tr");
        const status = row?.querySelector(".publish-status");

        if (status) {
          status.textContent = data.is_published ? "Yes" : "No";
        }
      } catch (error) {
        alert(error.message || "Something went wrong. Please try again.");
        button.textContent = originalText;
        button.dataset.published = String(wasPublished);
      } finally {
        button.disabled = false;
      }
    });
  });
});
