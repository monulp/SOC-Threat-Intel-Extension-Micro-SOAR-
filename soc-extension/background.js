chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "check-ip",
        title: "Deep Triage for '%s'",
        contexts: ["selection"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "check-ip") {
        const ip = info.selectionText.trim();
        // Save the right-clicked IP to storage, then open a small window
        chrome.storage.local.set({ searchTarget: ip }, () => {
            chrome.windows.create({
                url: "popup.html",
                type: "popup",
                width: 450,
                height: 650
            });
        });
    }
});
