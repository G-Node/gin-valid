window.addEventListener("load", function(evt) {
  var ws;
  var loc = window.location, new_uri;
  if (loc.protocol === "https:") {
    new_uri = "wss:";
  } else {
    new_uri = "ws:";
  }
  new_uri += "//" + loc.host + "/ws";
  ws = new WebSocket(new_uri);
  ws.onmessage = function(evt) {
    // there should be a check for the message
    // content, but it is not needed for now
    location.reload();
  }
});
