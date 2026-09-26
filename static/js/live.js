// Live event/job feed (TASK-043): target-scoped socket when ?target= is present,
// so a Target-A page never receives Target-B events.
(function () {
  var dot = document.getElementById("live-dot");
  function targetId() {
    try {
      var m = location.search.match(/[?&]target=(\d+)/);
      return m ? m[1] : null;
    } catch (e) { return null; }
  }
  function connect(path) {
    var proto = location.protocol === "https:" ? "wss" : "ws";
    var ws = new WebSocket(proto + "://" + location.host + path);
    ws.onopen = function () { if (dot) dot.classList.remove("off"); };
    ws.onclose = function () { if (dot) dot.classList.add("off"); setTimeout(function(){connect(path);}, 5000); };
    ws.onmessage = function (ev) {
      try {
        var d = JSON.parse(ev.data);
        // client-side guard (defense in depth; server already isolates)
        var tid = targetId();
        if (tid && d.target_id && String(d.target_id) !== String(tid)) return;
        var feed = document.getElementById("live-feed");
        if (feed) {
          var div = document.createElement("div");
          div.className = "ev";
          var label = d.event_type || d.type || "event";
          var asset = d.asset_value || d.job_type || "";
          div.innerHTML = "<span class='badge b-" + (d.severity || d.status || "INFO") + "'>" + label + "</span> " + asset;
          feed.prepend(div);
        }
      } catch (e) {}
    };
  }
  var tid = targetId();
  if (tid) connect("/ws/targets/" + tid + "/");
  else connect("/ws/events/");
})();
