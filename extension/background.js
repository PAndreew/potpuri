const DEFAULT_BASE_URL = "http://localhost:8080";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "page", title: "Add page to Potpuri", contexts: ["page"] });
  chrome.contextMenus.create({ id: "selection", title: "Add selection to Potpuri", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "link", title: "Add link to Potpuri", contexts: ["link"] });
  chrome.contextMenus.create({ id: "clipboard", title: "Add clipboard to Potpuri", contexts: ["all"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const text = info.selectionText || info.linkUrl || tab?.url || "";
  await capture({
    text,
    title: tab?.title || "Captured item",
    url: info.linkUrl || tab?.url || ""
  });
});

async function capture(payload) {
  const { baseUrl = DEFAULT_BASE_URL } = await chrome.storage.sync.get("baseUrl");
  await fetch(`${baseUrl.replace(/\/$/, "")}/api/clipboard`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
}
