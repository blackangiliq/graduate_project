<?php
// Safe counterpart of samples/vulnerable_app/index.php. Every finding here is a false positive.
$conn = new mysqli("localhost", "shop", getenv("DB_PASSWORD"), "shop");

$stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
$id = intval($_GET['id']);
$stmt->bind_param("i", $id);
$stmt->execute();

echo "<p>Results for " . htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";

$host = $_GET['host'] ?? '';
$output = shell_exec("ping -c 1 " . escapeshellarg($host));

$pages = ["home" => "pages/home.php", "about" => "pages/about.php"];
$page = $pages[$_GET['page'] ?? 'home'] ?? $pages['home'];
include $page;

$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);

$hash = password_hash($_POST['password'] ?? '', PASSWORD_DEFAULT);
$token = bin2hex(random_bytes(32));
$etag = md5($output);

header("Location: /home");
?>
