// Deliberately vulnerable browser code. FOR TESTING THE ANALYZER ONLY.

function showMessage() {
  const params = new URLSearchParams(window.location.search);
  const message = params.get("msg");
  document.getElementById("banner").innerHTML = message; // [F01]
}

function showFooter() {
  document.getElementById("footer").innerHTML = "<small>Shop demo</small>"; // [F02]
}

function showName(name) {
  document.getElementById("name").textContent = name; // [F03]
}

function track(page) {
  document.write("<img src='/track?page=" + page + "'>"); // [F04]
}

function runLater(code) {
  setTimeout("refresh(" + code + ")", 1000); // [F05]
}
