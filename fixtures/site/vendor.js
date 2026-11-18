// Harmless analytics-style script used as a negative fixture.
(function () {
  var queue = window._q = window._q || [];
  function track(name, props) {
    queue.push({ name: name, props: props || {}, ts: Date.now() });
  }
  window.addEventListener("load", function () {
    track("pageview", { path: location.pathname, title: document.title });
  });
  window.track = track;
})();
