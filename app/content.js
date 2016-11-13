var port = chrome.runtime.connect();

window.addEventListener("message", function(event) {

	// We only accept messages from ourselves
	if (event.source != window)
		return;

	if (event.data.type && (event.data.type == "FROM_PAGE")) {
		
		console.log("Content script received: " + event.data.text);

		chrome.extension.sendRequest(event.data.msg, function(data) {
			//console.log(data);
			window.postMessage({
	            type: "TO_PAGE",
	            text: data
	        }, "*");
		});

	}

}, false);