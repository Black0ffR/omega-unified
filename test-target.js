// Test target for OMEGA v5 — each section exercises a different module
// --- Ast Parser (Item 1) ---
var AppComponent = (function () {
    function AppComponent() { }
    AppComponent.prototype.ngOnInit = function () { };
    return AppComponent;
}());

// --- Crypto (Item 6) ---
var jwt = "eyJhbGciOiJIUzI1NiJ9.dGVzdA.abc123";
var token = "ghp_abcdefghijklmnopqrstuvwxyz123456";
var aesKey = "0123456789abcdef0123456789abcdef";

// --- Taint (Item 4) ---
document.addEventListener("DOMContentLoaded", function () {
    var urlParams = new URLSearchParams(window.location.search);
    var name = urlParams.get("name");
    document.getElementById("greeting").innerHTML = name;
});

// --- Network (Item 10) ---
fetch("https://api.example.com/v2/users", { method: "POST" });
var ws = new WebSocket("wss://internal.corp/socket");
var meta = "http://169.254.169.254/latest/meta-data/";

// --- Obfuscation (Item 14) — fromCharCode patterns ---
var hello = String.fromCharCode(72, 101, 108, 108, 111);
var world = String.fromCharCode(87, 111, 114, 108, 100);

// --- WASM (Item 15) — real WebAssembly patterns ---
WebAssembly.compile(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
var wasmB64 = "AGFzbQEAAAAB";

// --- Call-chain (Item 8) ---
document.getElementById("btn").addEventListener("click", function () {
    var input = document.getElementById("input").value;
    eval(input);
});
