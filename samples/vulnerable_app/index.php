<?php
// Deliberately vulnerable PHP page. FOR TESTING THE ANALYZER ONLY.
ini_set('display_errors', '1'); // [P01]
$conn = mysqli_connect("localhost", "shop", "Sh0p-Mysql-2024", "shop"); // [P02]

$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . $_GET['id']); // [P03]

$name = $_POST['name'];
$sql = "SELECT * FROM users WHERE name = '$name'"; // [P04]
$rows = mysqli_query($conn, $sql);

$stmt = $conn->prepare("SELECT * FROM users WHERE email = ?"); // [P05]
$stmt->bind_param("s", $_POST['email']);
$stmt->execute();

echo "<p>Results for " . $_GET['q'] . "</p>"; // [P06]
echo "<p>" . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . "</p>"; // [P07]

$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host); // [P08]
$checked = shell_exec("ping -c 1 " . escapeshellarg($host)); // [P09]

include($_GET['page'] . ".php"); // [P10]

$prefs = unserialize($_COOKIE['prefs']); // [P11]

$hash = md5($_POST['password']); // [P12]
$token = md5(uniqid()); // [P13]

header("Location: " . $_GET['next']); // [P14]

extract($_POST); // [P15]

move_uploaded_file($_FILES['doc']['tmp_name'], "uploads/" . $_FILES['doc']['name']); // [P16]

$backup_hash = hash('sha256', $output); // [P17]
?>
