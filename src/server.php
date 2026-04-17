<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$conn = new mysqli("127.0.0.1", "root", "", "adet_api_db", 3306);

if ($conn->connect_error) {
    echo json_encode(["status" => "error", "message" => "Database failed"]);
    exit;
}

$data = json_decode(file_get_contents("php://input"), true);

if (!isset($data['action'])) {
    echo json_encode(["status" => "error", "message" => "Action required"]);
    exit;
}

$action = $data['action'];

if ($action === "register") {

    if (!isset($data['username'], $data['password'], $data['email'], $data['role'])) {
        echo json_encode(["status" => "error", "message" => "All fields are required"]);
        exit;
    }

    $username = trim($data['username']);
    $password = trim($data['password']);
    $email    = trim($data['email']);
    $role     = trim($data['role']);

    if (strlen($username) < 3) {
        echo json_encode(["status" => "invalid", "message" => "Username must be at least 3 characters"]);
        exit;
    }

    if (strlen($password) < 4) {
        echo json_encode(["status" => "invalid", "message" => "Password must be at least 4 characters"]);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(["status" => "invalid", "message" => "Invalid email format"]);
        exit;
    }

    if ($role !== "student" && $role !== "faculty") {
        echo json_encode(["status" => "invalid", "message" => "Role must be student or faculty"]);
        exit;
    }

    $check = $conn->prepare("SELECT id FROM users WHERE username=? OR email=?");
    $check->bind_param("ss", $username, $email);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {
        echo json_encode(["status" => "exists", "message" => "User already exists"]);
        exit;
    }

    $hashed = password_hash($password, PASSWORD_DEFAULT);
    $insert = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)");
    $insert->bind_param("ssss", $username, $email, $hashed, $role);

    if ($insert->execute()) {
        echo json_encode([
            "status" => "success",
            "message" => "Registered successfully",
            "role" => $role
        ]);
    } else {
        echo json_encode(["status" => "error", "message" => "Registration failed"]);
    }
}

if ($action === "login") {
    if (!isset($data['username'], $data['password'])) {
        echo json_encode(["status" => "error", "message" => "Username & password required"]);
        exit;
    }

    $username = trim($data['username']);
    $password = trim($data['password']);

    $query = $conn->prepare("SELECT * FROM users WHERE username=?");
    $query->bind_param("s", $username);
    $query->execute();
    $result = $query->get_result();

    if ($result->num_rows === 0) {
        echo json_encode(["status" => "error", "message" => "User not found"]);
        exit;
    }

    $user = $result->fetch_assoc();

    if (password_verify($password, $user['password'])) {
        echo json_encode([
            "status" => "success",
            "message" => "Login successful",
            "role" => $user['role'] // ✅ Checked: singular
        ]);
    } else {
        echo json_encode(["status" => "error", "message" => "Wrong password"]);
    }
}
?>