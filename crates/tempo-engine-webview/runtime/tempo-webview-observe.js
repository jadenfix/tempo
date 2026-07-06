(() => {
  const roleFor = (element) => {
    const explicit = element.getAttribute("role");
    if (explicit) return explicit;
    const tag = element.tagName.toLowerCase();
    if (tag === "button") return "button";
    if (tag === "a") return "link";
    if (tag === "textarea") return "textbox";
    if (tag === "select") return "combobox";
    if (tag === "input") {
      const type = (element.getAttribute("type") || "text").toLowerCase();
      if (type === "checkbox") return "checkbox";
      if (type === "radio") return "radio";
      if (type === "search") return "searchbox";
      if (type === "range") return "slider";
      return "textbox";
    }
    return tag;
  };

  const accessibleName = (element) => {
    const labelledBy = element.getAttribute("aria-labelledby");
    if (labelledBy) {
      const text = labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.innerText || "")
        .join(" ")
        .trim();
      if (text) return text;
    }
    return (
      element.getAttribute("aria-label") ||
      element.getAttribute("alt") ||
      element.getAttribute("title") ||
      element.labels?.[0]?.innerText ||
      element.innerText ||
      element.value ||
      ""
    ).trim();
  };

  const pageSpans = (text) => {
    const normalized = (text || "").trim();
    if (!normalized) return [];
    return [{ provenance: "page", text: normalized }];
  };

  const stableHint = (element) => {
    const parts = [
      element.getAttribute("data-tempo-id"),
      element.id,
      element.getAttribute("name"),
      element.getAttribute("href"),
      element.getAttribute("type"),
      roleFor(element),
      accessibleName(element),
    ].filter(Boolean);
    return parts.join("|") || null;
  };

  const selectorFor = (element, index) => {
    if (element.id) return `#${CSS.escape(element.id)}`;
    const tempoId = element.getAttribute("data-tempo-id");
    if (tempoId) return `[data-tempo-id="${CSS.escape(tempoId)}"]`;
    return `[data-tempo-source="${index}"]`;
  };

  window.__tempoCollectObservation = () => {
    const selector = [
      "a[href]",
      "button",
      "input",
      "select",
      "textarea",
      "[role]",
      "[contenteditable=true]",
      "[tabindex]",
    ].join(",");
    const elements = Array.from(document.querySelectorAll(selector));
    return {
      url: window.location.href,
      elements: elements.map((element, index) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        const visible =
          rect.width > 0 &&
          rect.height > 0 &&
          style.visibility !== "hidden" &&
          style.display !== "none";
        return {
          locator: selectorFor(element, index),
          source_id: element.getAttribute("data-tempo-source") || null,
          stable_hint: stableHint(element),
          role: roleFor(element),
          name: pageSpans(accessibleName(element)),
          value: pageSpans(element.value || ""),
          bounds: [rect.x, rect.y, rect.width, rect.height],
          visible,
          enabled: !element.disabled,
          interactive: visible,
        };
      }),
    };
  };
})();
