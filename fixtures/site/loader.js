// Mimics an A/B-testing snippet that loads its experiment code at runtime.
(function () {
  var s = document.createElement("script");
  s.src = "/exp.js";
  document.head.appendChild(s);
})();
