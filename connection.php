<?php
// Shared PDO connection for the Clothing Shop Management System.
$servername = getenv('CLOTHING_DB_HOST') ?: 'localhost';
$username = getenv('CLOTHING_DB_USER') ?: 'root';
$password = getenv('CLOTHING_DB_PASSWORD') ?: '';
$dbname = getenv('CLOTHING_DB_NAME') ?: 'clothing';

try {
    $dsn = "mysql:host=$servername;dbname=$dbname;charset=utf8mb4";
    $conn = new PDO($dsn, $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Log connection details privately; the login/registration page shows a safe message.
    error_log('Clothing shop database connection failed: ' . $e->getMessage());
    throw $e;
}