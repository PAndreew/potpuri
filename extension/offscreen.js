chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.target !== "offscreen" || message.type !== "read-clipboard") {
    return false;
  }
  navigator.clipboard.readText()
    .then((text) => sendResponse({ text }))
    .catch((error) => sendResponse({ error: error.message }));
  return true;
});
