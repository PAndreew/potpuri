const DEFAULT_BASE_URL = "https://potpuri.cc";
const baseUrlInput = document.querySelector("#baseUrl");
const apiTokenInput = document.querySelector("#apiToken");
const status = document.querySelector("#status");

Promise.all([
  chrome.storage.sync.get("baseUrl"),
  chrome.storage.local.get("apiToken")
]).then(([{ baseUrl }, { apiToken }]) => {
  baseUrlInput.value = baseUrl || DEFAULT_BASE_URL;
  apiTokenInput.value = apiToken || "";
});

document.querySelector("#save").addEventListener("click", async () => {
  const baseUrl = baseUrlInput.value.trim().replace(/\/$/, "");
  const apiToken = apiTokenInput.value.trim();
  if (!isAllowedBaseUrl(baseUrl) || !apiToken) {
    status.textContent = "Enter a valid URL and token.";
    return;
  }
  await Promise.all([
    chrome.storage.sync.set({ baseUrl }),
    chrome.storage.local.set({ apiToken })
  ]);
  status.textContent = "Saved.";
  setTimeout(() => { status.textContent = ""; }, 2000);
});

function isAllowedBaseUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" ||
      (url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname));
  } catch {
    return false;
  }
}
