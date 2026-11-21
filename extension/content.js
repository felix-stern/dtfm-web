// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

// Strictly read-only DOM extractor for dtfm-web.
// Loaded on-demand via chrome.scripting.executeScript (and directly testable in Node).
// NEVER mutates page state, clicks buttons, or submits forms.

(function initDtfmWebContent(root) {
  const CSRF_NAME_RE = /(?:^|[_-])(csrf|xsrf|authenticity[_-]?token|requestverificationtoken|verification[_-]?token|__viewstate|__eventvalidation|session[_-]?token)(?:$|[_-])/i;
  const SKIP_INPUT_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

  function cleanText(str) {
    if (typeof str !== "string") return "";
    return str.replace(/\s+/g, " ").trim();
  }

  function isElementHidden(el, doc) {
    if (!el) return true;
    if (el.hidden) return true;
    const ariaHidden = el.getAttribute && el.getAttribute("aria-hidden");
    if (ariaHidden === "true") return true;
    if (el.style && (el.style.display === "none" || el.style.visibility === "hidden")) {
      return true;
    }
    const win = doc && doc.defaultView;
    if (win && typeof win.getComputedStyle === "function") {
      try {
        const cs = win.getComputedStyle(el);
        if (cs && (cs.display === "none" || cs.visibility === "hidden")) {
          return true;
        }
      } catch (_) {
        // Ignore computed style errors in detached/mocked DOMs.
      }
    }
    return false;
  }

  function isVisible(el, doc) {
    let cur = el;
    while (cur && cur.nodeType === 1) {
      if (isElementHidden(cur, doc)) {
        return false;
      }
      cur = cur.parentElement;
    }
    return true;
  }

  function extractTextExcludingControls(node) {
    if (!node) return "";
    if (node.nodeType === 3) {
      return node.nodeValue || "";
    }
    if (node.nodeType !== 1) {
      return "";
    }
    const tag = (node.tagName || "").toUpperCase();
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA" || tag === "SCRIPT" || tag === "STYLE") {
      return "";
    }
    let out = "";
    const children = node.childNodes || [];
    for (let i = 0; i < children.length; i++) {
      out += extractTextExcludingControls(children[i]);
    }
    return out;
  }

  function findLabelByFor(el, doc) {
    const id = el.id || (el.getAttribute && el.getAttribute("id"));
    if (!id || !doc || typeof doc.querySelectorAll !== "function") return "";
    const labels = doc.querySelectorAll("label[for]");
    for (let i = 0; i < labels.length; i++) {
      if (labels[i].getAttribute("for") === id) {
        const txt = cleanText(extractTextExcludingControls(labels[i]));
        if (txt) return txt;
      }
    }
    return "";
  }

  function findWrappingLabel(el) {
    if (typeof el.closest === "function") {
      const label = el.closest("label");
      if (label) {
        const txt = cleanText(extractTextExcludingControls(label));
        if (txt) return txt;
      }
    } else {
      let cur = el.parentElement;
      while (cur) {
        if ((cur.tagName || "").toUpperCase() === "LABEL") {
          const txt = cleanText(extractTextExcludingControls(cur));
          if (txt) return txt;
        }
        cur = cur.parentElement;
      }
    }
    return "";
  }

  function findAriaLabel(el, doc) {
    if (!el.getAttribute) return "";
    const ariaLabel = cleanText(el.getAttribute("aria-label") || "");
    if (ariaLabel) return ariaLabel;

    const labelledBy = cleanText(el.getAttribute("aria-labelledby") || "");
    if (labelledBy && doc && typeof doc.getElementById === "function") {
      const parts = labelledBy.split(/\s+/);
      const texts = [];
      for (const refId of parts) {
        const refEl = doc.getElementById(refId);
        if (refEl) {
          const t = cleanText(refEl.textContent || "");
          if (t) texts.push(t);
        }
      }
      if (texts.length > 0) {
        return texts.join(" ");
      }
    }
    return "";
  }

  function findTableCellLabel(el) {
    let cell = null;
    if (typeof el.closest === "function") {
      cell = el.closest("td, th");
    } else {
      let cur = el.parentElement;
      while (cur) {
        const tag = (cur.tagName || "").toUpperCase();
        if (tag === "TD" || tag === "TH") {
          cell = cur;
          break;
        }
        cur = cur.parentElement;
      }
    }
    if (!cell) return "";

    // 1. Check previous sibling <th> or <td> in the same <tr>.
    const row = typeof cell.closest === "function" ? cell.closest("tr") : cell.parentElement;
    if (row && row.children) {
      const cells = Array.from(row.children).filter((c) => {
        const t = (c.tagName || "").toUpperCase();
        return t === "TH" || t === "TD";
      });
      const idx = cells.indexOf(cell);
      for (let i = idx - 1; i >= 0; i--) {
        const txt = cleanText(extractTextExcludingControls(cells[i]));
        if (txt) return txt;
      }

      // 2. Fall back to column header <th> in enclosing <table>.
      const table = typeof row.closest === "function" ? row.closest("table") : null;
      if (table && idx >= 0 && typeof table.querySelectorAll === "function") {
        const headerRows = table.querySelectorAll("thead tr");
        const firstRow = headerRows.length > 0 ? headerRows[0] : table.querySelector("tr");
        if (firstRow && firstRow !== row && firstRow.children) {
          const headerCells = Array.from(firstRow.children).filter((c) => {
            const t = (c.tagName || "").toUpperCase();
            return t === "TH" || t === "TD";
          });
          if (idx < headerCells.length) {
            const txt = cleanText(extractTextExcludingControls(headerCells[idx]));
            if (txt) return txt;
          }
        }
      }
    }
    return "";
  }

  function resolveLabel(el, doc) {
    // Resolution order:
    // 1. <label for>
    // 2. wrapping <label>
    // 3. aria-label / aria-labelledby
    // 4. nearest table <th>/<td>
    // 5. placeholder / name / id
    return (
      findLabelByFor(el, doc) ||
      findWrappingLabel(el) ||
      findAriaLabel(el, doc) ||
      findTableCellLabel(el) ||
      cleanText((el.getAttribute && el.getAttribute("placeholder")) || el.placeholder || "") ||
      cleanText((el.getAttribute && el.getAttribute("name")) || el.name || "") ||
      cleanText(el.id || (el.getAttribute && el.getAttribute("id")) || "") ||
      ""
    );
  }

  function extractHeadings(doc) {
    const out = [];
    if (!doc || typeof doc.querySelectorAll !== "function") return out;
    const nodes = doc.querySelectorAll("h1, h2, h3");
    for (let i = 0; i < nodes.length; i++) {
      const el = nodes[i];
      if (!isVisible(el, doc)) continue;
      const text = cleanText(el.textContent || "");
      if (!text) continue;
      const level = Number((el.tagName || "H1").slice(1)) || 1;
      out.push({ level, text });
    }
    return out;
  }

  function extractAlerts(doc) {
    const out = [];
    const seen = new Set();
    if (!doc || typeof doc.querySelectorAll !== "function") return out;
    const nodes = doc.querySelectorAll('[role="alert"], [aria-live="assertive"], .alert-danger, .alert-error, .error-banner, [data-error]');
    for (let i = 0; i < nodes.length; i++) {
      const el = nodes[i];
      if (!isVisible(el, doc)) continue;
      const text = cleanText(el.textContent || "");
      if (!text || seen.has(text)) continue;
      seen.add(text);
      out.push(text);
    }
    return out;
  }

  function extractFields(doc) {
    const out = [];
    if (!doc || typeof doc.querySelectorAll !== "function") return out;
    const nodes = doc.querySelectorAll("input, select, textarea");
    for (let i = 0; i < nodes.length; i++) {
      const el = nodes[i];
      const tag = (el.tagName || "").toLowerCase();
      const name = cleanText((el.getAttribute && el.getAttribute("name")) || el.name || "");
      const id = cleanText(el.id || (el.getAttribute && el.getAttribute("id")) || "");

      let fieldType = tag;
      if (tag === "input") {
        fieldType = cleanText((el.getAttribute && el.getAttribute("type")) || el.type || "text").toLowerCase();
        if (!fieldType) fieldType = "text";
        if (SKIP_INPUT_TYPES.has(fieldType)) {
          continue;
        }
      }

      // Omit hidden CSRF/session inputs even if disguised as non-hidden input types.
      if (!isVisible(el, doc) && (CSRF_NAME_RE.test(name) || CSRF_NAME_RE.test(id))) {
        continue;
      }

      const field = {
        tag,
        type: fieldType,
        label: resolveLabel(el, doc),
        name,
        id,
        readonly: Boolean(el.readOnly || (el.hasAttribute && el.hasAttribute("readonly"))),
        disabled: Boolean(el.disabled || (el.hasAttribute && el.hasAttribute("disabled"))),
        required: Boolean(el.required || (el.hasAttribute && el.hasAttribute("required"))),
      };

      if (tag === "input" && fieldType === "password") {
        field.value = "[REDACTED]";
      } else if (tag === "input" && (fieldType === "checkbox" || fieldType === "radio")) {
        field.checked = Boolean(el.checked);
        field.value = el.value !== undefined ? String(el.value) : "";
      } else if (tag === "select") {
        field.multiple = Boolean(el.multiple);
        const options = [];
        const selectedOptions = [];
        const optNodes = el.options ? Array.from(el.options) : (typeof el.querySelectorAll === "function" ? Array.from(el.querySelectorAll("option")) : []);
        for (let j = 0; j < optNodes.length; j++) {
          const opt = optNodes[j];
          const optObj = {
            value: opt.value !== undefined ? String(opt.value) : cleanText(opt.textContent || ""),
            text: cleanText(opt.textContent || opt.text || ""),
            selected: Boolean(opt.selected),
            disabled: Boolean(opt.disabled),
          };
          options.push(optObj);
          if (optObj.selected) {
            selectedOptions.push(optObj.value);
          }
        }
        field.value = el.value !== undefined ? String(el.value) : (selectedOptions[0] || "");
        field.selected_options = selectedOptions;
        field.options = options;
      } else {
        field.value = el.value !== undefined ? String(el.value) : "";
      }

      out.push(field);
    }
    return out;
  }

  function extractPageDOM(doc) {
    const targetDoc = doc || (typeof document !== "undefined" ? document : null);
    if (!targetDoc) {
      throw new Error("document is unavailable");
    }
    return {
      title: cleanText(targetDoc.title || ""),
      url: (targetDoc.location && targetDoc.location.href) || "",
      headings: extractHeadings(targetDoc),
      alerts: extractAlerts(targetDoc),
      fields: extractFields(targetDoc),
    };
  }

  function formatDOMAsMarkdown(snapshot) {
    const lines = [];
    lines.push(`# ${snapshot.title || "(Untitled Page)"}`);
    if (snapshot.url) {
      lines.push(`URL: ${snapshot.url}`);
    }
    lines.push("");

    if (snapshot.alerts && snapshot.alerts.length > 0) {
      lines.push("## Alerts");
      for (const alert of snapshot.alerts) {
        lines.push(`- ${alert}`);
      }
      lines.push("");
    }

    if (snapshot.headings && snapshot.headings.length > 0) {
      lines.push("## Headings");
      for (const h of snapshot.headings) {
        const prefix = "#".repeat(Math.min(Math.max(h.level || 1, 1), 3));
        lines.push(`- ${prefix} ${h.text}`);
      }
      lines.push("");
    }

    lines.push("## Form Controls");
    if (!snapshot.fields || snapshot.fields.length === 0) {
      lines.push("_No form controls found._");
    } else {
      for (let i = 0; i < snapshot.fields.length; i++) {
        const f = snapshot.fields[i];
        const label = f.label || f.name || f.id || `(unnamed ${f.type})`;
        const flags = [];
        if (f.required) flags.push("required");
        if (f.readonly) flags.push("readonly");
        if (f.disabled) flags.push("disabled");
        const flagStr = flags.length > 0 ? ` [${flags.join(", ")}]` : "";

        if (f.type === "checkbox" || f.type === "radio") {
          const mark = f.checked ? "x" : " ";
          const valSuffix = f.value && f.value !== "on" ? ` (value=${JSON.stringify(f.value)})` : "";
          lines.push(`${i + 1}. [${mark}] **${label}** (${f.type})${valSuffix}${flagStr}`);
        } else if (f.tag === "select") {
          const opts = (f.options || [])
            .map((o) => `${o.selected ? "*" : ""}${o.text || o.value}${o.disabled ? " (disabled)" : ""}`)
            .join(" | ");
          lines.push(
            `${i + 1}. **${label}** (select): ${JSON.stringify(f.value || "")}${flagStr}` +
              (opts ? ` — options: [${opts}]` : "")
          );
        } else {
          lines.push(`${i + 1}. **${label}** (${f.type}): ${JSON.stringify(f.value ?? "")}${flagStr}`);
        }
      }
    }

    return lines.join("\n").trimEnd() + "\n";
  }

  function runExtract(format, doc) {
    const fmt = format === "json" ? "json" : "md";
    const snapshot = extractPageDOM(doc);
    if (fmt === "json") {
      return { format: "json", dom: snapshot };
    }
    return { format: "md", markdown: formatDOMAsMarkdown(snapshot), dom: snapshot };
  }

  // Expose for chrome.scripting.executeScript and Node tests.
  root.__dtfmWebExtract = runExtract;
  root.__dtfmWebExtractor = {
    extractPageDOM,
    formatDOMAsMarkdown,
    runExtract,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
