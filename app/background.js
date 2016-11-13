var application = 'com.aconos.erp';
var port = null;
var sendResponseCallback = null;

function sendNativeMessage(msg, sendResponse) {
	if (port) {
	    console.log('port.postMessage');
	    port.postMessage(msg);
	} else {
	    console.log('chrome.runtime.sendNativeMessage');
	    chrome.runtime.sendNativeMessage(application, msg, function(data) {
	    	console.log(data);
	    	sendResponse(data);
	    });
	}
}

function connect(sendResponse) {
    // connect to local program com.a.chrome_interface
    port = chrome.extension.connectNative(application);
    port.onMessage.addListener(sendResponseCallback);
    //port.onMessage.addListener(log);
}

chrome.extension.onRequest.addListener(function(data, sender, sendResponse) {
	sendResponseCallback = sendResponse;
    connect();
    sendNativeMessage(data, sendResponse);
});