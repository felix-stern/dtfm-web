// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contentSrc = fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8");

function loadExtractor() {
  const sandbox = {};
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.runInNewContext(contentSrc, sandbox);
  return sandbox.__dtfmWebExtractor;
}

// Lightweight DOM mock supporting selectors, parentElement/closest, attributes, text nodes.
class MockNode {
  constructor(nodeType, nodeValue = "") {
    this.nodeType = nodeType;
    this.nodeValue = nodeValue;
    this.parentElement = null;
  }
}

class MockElement extends MockNode {
  constructor(tagName, attrs = {}, props = {}) {
    super(1, "");
    this.tagName = tagName.toUpperCase();
    this.attrs = { ...attrs };
    this.childNodes = [];
    this.children = [];
    this.style = props.style || {};
    this.hidden = Boolean(props.hidden);
    this.value = props.value ?? attrs.value ?? "";
    this.checked = Boolean(props.checked);
    this.readOnly = Boolean(props.readOnly || "readonly" in attrs);
    this.disabled = Boolean(props.disabled || "disabled" in attrs);
    this.required = Boolean(props.required || "required" in attrs);
    this.multiple = Boolean(props.multiple || "multiple" in attrs);
    this.selected = Boolean(props.selected || "selected" in attrs);
    this.id = attrs.id || "";
    this.name = attrs.name || "";
    this.type = attrs.type || "";
    this.placeholder = attrs.placeholder || "";
  }

  append(...nodes) {
    for (const n of nodes) {
      if (typeof n === "string") {
        const tn = new MockNode(3, n);
        tn.parentElement = this;
        this.childNodes.push(tn);
      } else {
        n.parentElement = this;
        this.childNodes.push(n);
        if (n.nodeType === 1) this.children.push(n);
      }
    }
    return this;
  }

  get textContent() {
    let out = "";
    for (const c of this.childNodes) {
      out += c.nodeType === 3 ? c.nodeValue : c.textContent;
    }
    return out;
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }

  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name);
  }

  matchesSingle(sel) {
    sel = sel.trim();
    if (sel.startsWith("[") && sel.endsWith("]")) {
      const inner = sel.slice(1, -1);
      const eq = inner.indexOf("=");
      if (eq === -1) return this.hasAttribute(inner);
      const k = inner.slice(0, eq);
      const v = inner.slice(eq + 1).replace(/^["']|["']$/g, "");
      return this.getAttribute(k) === v;
    }
    if (sel.startsWith(".")) {
      const cls = (this.getAttribute("class") || "").split(/\s+/);
      return cls.includes(sel.slice(1));
    }
    const attrIdx = sel.indexOf("[");
    if (attrIdx > 0) {
      const tag = sel.slice(0, attrIdx).toUpperCase();
      return this.tagName === tag && this.matchesSingle(sel.slice(attrIdx));
    }
    return this.tagName === sel.toUpperCase();
  }

  matches(selector) {
    return selector.split(",").some((part) => {
      const tokens = part.trim().split(/\s+/);
      if (tokens.length === 1) return this.matchesSingle(tokens[0]);
      if (!this.matchesSingle(tokens[tokens.length - 1])) return false;
      let cur = this.parentElement;
      for (let i = tokens.length - 2; i >= 0; i--) {
        let found = false;
        while (cur) {
          if (cur.matchesSingle(tokens[i])) {
            found = true;
            cur = cur.parentElement;
            break;
          }
          cur = cur.parentElement;
        }
        if (!found) return false;
      }
      return true;
    });
  }

  closest(selector) {
    let cur = this;
    while (cur) {
      if (cur.matches(selector)) return cur;
      cur = cur.parentElement;
    }
    return null;
  }

  querySelectorAll(selector) {
    const res = [];
    const walk = (el) => {
      for (const child of el.children) {
        if (child.matches(selector)) res.push(child);
        walk(child);
      }
    };
    walk(this);
    return res;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

function el(tag, attrs, props, ...children) {
  const node = new MockElement(tag, attrs, props);
  node.append(...children);
  return node;
}

function makeDoc({ title, url, body }) {
  return {
    title,
    location: { href: url },
    defaultView: null,
    querySelectorAll: (sel) => body.querySelectorAll(sel),
    querySelector: (sel) => body.querySelector(sel),
    getElementById: (id) => {
      const all = body.querySelectorAll("div, span, label, p, h1, h2, h3, input, select, textarea, th, td");
      return all.find((n) => n.id === id) || null;
    },
  };
}

test("DOM extraction: label resolution, password redaction, hidden field omission, and md/json formatting", () => {
  const { extractPageDOM, formatDOMAsMarkdown, runExtract } = loadExtractor();

  const body = el("body", {}, {},
    el("h1", {}, {}, "Tax Declaration Portal"),
    el("h2", {}, {}, "Step 2: Income"),
    el("h3", {}, { hidden: true }, "Hidden Heading Should Be Ignored"),
    el("div", { role: "alert" }, {}, "Please verify your AHV number."),
    el("div", { role: "alert", "aria-hidden": "true" }, {}, "Invisible alert"),
    el("form", {}, {},
      // Hidden CSRF token (type="hidden") -> must be omitted
      el("input", { type: "hidden", name: "csrf_token", value: "secret-csrf-123" }),
      // Visually hidden session token -> must be omitted
      el("input", { type: "text", name: "_csrf", value: "disguised-csrf" }, { style: { display: "none" } }),
      // 1. <label for="email">
      el("label", { for: "email" }, {}, "Email Address"),
      el("input", { id: "email", type: "email", name: "user_email", required: "" }, { value: "ivan@example.ch" }),
      // 2. Wrapping <label>
      el("label", {}, {}, "Accept terms ", el("input", { type: "checkbox", name: "tos" }, { checked: true, value: "yes" })),
      // 3. aria-label
      el("input", { type: "password", "aria-label": "Account Password", name: "pwd" }, { value: "SuperSecret!99" }),
      // 4. aria-labelledby
      el("span", { id: "lbl-canton" }, {}, "Canton of Residence"),
      el("select", { "aria-labelledby": "lbl-canton", name: "canton" }, { value: "ZH" },
        el("option", { value: "ZH" }, { selected: true }, "Zurich"),
        el("option", { value: "GE" }, { selected: false }, "Geneva"),
        el("option", { value: "BS", disabled: "" }, { selected: false, disabled: true }, "Basel-Stadt")
      ),
      // 5. Table <th>/<td> label
      el("table", {}, {},
        el("tr", {}, {},
          el("th", {}, {}, "Gross Salary (CHF)"),
          el("td", {}, {}, el("input", { type: "text", name: "salary", readonly: "" }, { value: "120000" }))
        )
      ),
      // 6. Placeholder / name fallback
      el("textarea", { placeholder: "Additional Notes", name: "notes", disabled: "" }, { value: "None" }),
      // Radio button
      el("label", { for: "r-single" }, {}, "Single"),
      el("input", { id: "r-single", type: "radio", name: "marital" }, { value: "single", checked: false }),
      // Submit button should be omitted
      el("input", { type: "submit", value: "Continue" })
    )
  );

  const doc = makeDoc({
    title: "ZHprivateTax — Step 2",
    url: "https://zh.ch/tax/step2",
    body,
  });

  const snap = JSON.parse(JSON.stringify(extractPageDOM(doc)));
  assert.equal(snap.title, "ZHprivateTax — Step 2");
  assert.equal(snap.url, "https://zh.ch/tax/step2");
  assert.deepEqual(snap.headings, [
    { level: 1, text: "Tax Declaration Portal" },
    { level: 2, text: "Step 2: Income" },
  ]);
  assert.deepEqual(snap.alerts, ["Please verify your AHV number."]);

  // Verify CSRF hidden inputs and submit button are omitted
  assert.equal(snap.fields.length, 7);
  assert.equal(snap.fields.some((f) => f.name === "csrf_token" || f.name === "_csrf"), false);

  // 1. label[for]
  assert.equal(snap.fields[0].label, "Email Address");
  assert.equal(snap.fields[0].value, "ivan@example.ch");
  assert.equal(snap.fields[0].required, true);

  // 2. wrapping <label> + checkbox
  assert.equal(snap.fields[1].label, "Accept terms");
  assert.equal(snap.fields[1].type, "checkbox");
  assert.equal(snap.fields[1].checked, true);

  // 3. aria-label + password redaction
  assert.equal(snap.fields[2].label, "Account Password");
  assert.equal(snap.fields[2].type, "password");
  assert.equal(snap.fields[2].value, "[REDACTED]");

  // 4. aria-labelledby + select options
  assert.equal(snap.fields[3].label, "Canton of Residence");
  assert.equal(snap.fields[3].tag, "select");
  assert.equal(snap.fields[3].value, "ZH");
  assert.equal(snap.fields[3].options.length, 3);
  assert.equal(snap.fields[3].options[0].selected, true);
  assert.equal(snap.fields[3].options[2].disabled, true);

  // 5. table <th> + readonly
  assert.equal(snap.fields[4].label, "Gross Salary (CHF)");
  assert.equal(snap.fields[4].value, "120000");
  assert.equal(snap.fields[4].readonly, true);

  // 6. placeholder fallback + disabled
  assert.equal(snap.fields[5].label, "Additional Notes");
  assert.equal(snap.fields[5].disabled, true);

  // 7. radio
  assert.equal(snap.fields[6].label, "Single");
  assert.equal(snap.fields[6].type, "radio");
  assert.equal(snap.fields[6].checked, false);

  // Markdown formatting checks
  const md = formatDOMAsMarkdown(snap);
  assert.match(md, /# ZHprivateTax — Step 2/);
  assert.match(md, /## Alerts/);
  assert.match(md, /Please verify your AHV number\./);
  assert.match(md, /\*\*Account Password\*\* \(password\): "\[REDACTED\]"/);
  assert.match(md, /\[readonly\]/);
  assert.match(md, /\[disabled\]/);
  assert.match(md, /\*Zurich \| Geneva \| Basel-Stadt \(disabled\)/);
  assert.doesNotMatch(md, /SuperSecret!99/);
  assert.doesNotMatch(md, /secret-csrf-123/);

  // runExtract format dispatch
  const jsonRes = runExtract("json", doc);
  assert.equal(jsonRes.format, "json");
  assert.equal(jsonRes.dom.fields.length, 7);

  const mdRes = runExtract("md", doc);
  assert.equal(mdRes.format, "md");
  assert.equal(mdRes.markdown, md);
  assert.equal("dom" in mdRes, false);
});
