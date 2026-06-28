const DEFAULT_BASE_URL = "https://potpuri.cc";
const OFFSCREEN_DOCUMENT = "offscreen.html";

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await createContextMenus();
  if (reason === "install") {
    await chrome.runtime.openOptionsPage();
  }
});

chrome.action.onClicked.addListener((tab) => {
  void saveCapture(pageCapture(tab));
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  void handleContextMenu(info, tab);
});

async function createContextMenus() {
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({ id: "page", title: "Add page to Potpuri", contexts: ["page"] });
  chrome.contextMenus.create({ id: "selection", title: "Add selection to Potpuri", contexts: ["selection"] });
  chrome.contextMenus.create({ id: "link", title: "Add link to Potpuri", contexts: ["link"] });
  chrome.contextMenus.create({ id: "clipboard", title: "Add clipboard to Potpuri", contexts: ["all"] });
}

async function handleContextMenu(info, tab) {
  switch (info.menuItemId) {
    case "selection":
      await saveCapture({
        title: tab?.title || "Selected text",
        text: info.selectionText || "",
        url: tab?.url || ""
      });
      break;
    case "link":
      await saveCapture({ title: "", text: "", url: info.linkUrl || "" });
      break;
    case "clipboard":
      await saveCapture({ title: "Clipboard", text: await readClipboard(), url: "" });
      break;
    default:
      await saveCapture(pageCapture(tab));
  }
}

function pageCapture(tab) {
  return {
    title: tab?.title || "Captured page",
    text: "",
    url: tab?.url || ""
  };
}

async function saveCapture(payload) {
  try {
    const [{ baseUrl = DEFAULT_BASE_URL }, { apiToken = "" }] = await Promise.all([
      chrome.storage.sync.get("baseUrl"),
      chrome.storage.local.get("apiToken")
    ]);
    if (!apiToken) {
      await chrome.runtime.openOptionsPage();
      throw new Error("Add your Potpuri API token in the extension options");
    }

    const response = await fetch(`${baseUrl.replace(/\/$/, "")}/api/clipboard`, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${apiToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new Error(message || `Potpuri returned ${response.status}`);
    }
    await showBadge("OK", "#16794b");
  } catch (error) {
    console.error("Potpuri capture failed", error);
    await showBadge("!", "#b42318");
  }
}

async function showBadge(text, color) {
  await chrome.action.setBadgeBackgroundColor({ color });
  await chrome.action.setBadgeText({ text });
  setTimeout(() => chrome.action.setBadgeText({ text: "" }), 2000);
}

async function readClipboard() {
  const offscreenUrl = chrome.runtime.getURL(OFFSCREEN_DOCUMENT);
  const contexts = await chrome.runtime.getContexts({
    contextTypes: ["OFFSCREEN_DOCUMENT"],
    documentUrls: [offscreenUrl]
  });
  if (contexts.length === 0) {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_DOCUMENT,
      reasons: ["CLIPBOARD"],
      justification: "Read clipboard text after the user selects Add clipboard"
    });
  }

  const result = await chrome.runtime.sendMessage({ target: "offscreen", type: "read-clipboard" });
  if (result?.error) {
    throw new Error(result.error);
  }
  return result?.text || "";
}
