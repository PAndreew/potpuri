const input = document.querySelector("#baseUrl");
chrome.storage.sync.get("baseUrl").then(({ baseUrl }) => {
  input.value = baseUrl || "http://localhost:8080";
});
document.querySelector("#save").addEventListener("click", async () => {
  await chrome.storage.sync.set({ baseUrl: input.value });
});
