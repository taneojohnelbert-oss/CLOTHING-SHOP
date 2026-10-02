<?php
/**
 * Clothing Shop Management System â€” customer registration
 * Uses the same users table as login.php:
 * users(id, email, password_hash, role, status)
 * Configure CLOTHING_DB_HOST, CLOTHING_DB_NAME, CLOTHING_DB_USER,
 * and CLOTHING_DB_PASSWORD if your local MySQL settings differ.
 */
declare(strict_types=1);

$isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params(['httponly'=>true, 'secure'=>$isHttps, 'samesite'=>'Lax']);
$sessionPathCandidates = [
    __DIR__ . DIRECTORY_SEPARATOR . 'sessions',
    rtrim(sys_get_temp_dir(), "\\/") . DIRECTORY_SEPARATOR . 'thread-form-sessions',
];
$sessionStorage = null;
foreach ($sessionPathCandidates as $candidate) {
    if (!is_dir($candidate) && !@mkdir($candidate, 0700, true) && !is_dir($candidate)) {
        continue;
    }
    if (is_writable($candidate)) {
        $sessionStorage = $candidate;
        break;
    }
}
if ($sessionStorage === null || session_save_path($sessionStorage) === false) {
    http_response_code(500);
    exit('Session storage is not writable. Configure a writable PHP session directory.');
}
session_start();
if (empty($_SESSION['register_csrf'])) {
    $_SESSION['register_csrf'] = bin2hex(random_bytes(32));
}
$error = '';
$created = false;
$email = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $postedToken = (string)($_POST['csrf_token'] ?? '');
    $email = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $confirmation = (string)($_POST['password_confirmation'] ?? '');

    if (!hash_equals((string)$_SESSION['register_csrf'], $postedToken)) {
        $error = 'Your session expired. Refresh the page and try again.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        $error = 'Enter a valid email address.';
    } elseif (strlen($password) < 6) {
        $error = 'Your password must be at least 6 characters.';
    } elseif (!hash_equals($password, $confirmation)) {
        $error = 'The passwords do not match.';
    } else {
        try {
            require __DIR__ . '/connection.php';
            $pdo = $conn;
            $check = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $check->execute(['email'=>$email]);
            if ($check->fetch()) {
                $error = 'An account with this email already exists. Try signing in.';
            } else {
                $insert = $pdo->prepare('INSERT INTO users (email, password_hash, role, status) VALUES (:email, :password_hash, :role, :status)');
                $insert->execute([
                    'email'=>$email,
                    'password_hash'=>password_hash($password, PASSWORD_DEFAULT),
                    'role'=>'Customer',
                    'status'=>'Active',
                ]);
                $created = true;
                $_SESSION['register_csrf'] = bin2hex(random_bytes(32));
            }
        } catch (PDOException $exception) {
            // Duplicate-key errors can occur if two sign-ups use the same address at once.
            if ($exception->getCode() === '23000') {
                $error = 'An account with this email already exists. Try signing in.';
            } else {
                error_log('Clothing shop registration database error: ' . $exception->getMessage());
                $error = 'Registration is temporarily unavailable. Check the database connection and try again.';
            }
        }
    }
}
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Create account Â· Thread &amp; Form</title>
<style>
:root{--ink:#24241f;--muted:#77776e;--paper:#faf9f6;--line:#e9e7e0;--olive:#68745b;--olive-dark:#4d5b42}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.topline{background:#34372f;color:#f8f7f2;text-align:center;padding:9px 14px;font-size:11px;letter-spacing:.09em}.brand{font:600 20px Georgia,serif;letter-spacing:.05em;color:inherit;text-decoration:none}.brand small{display:block;font:10px/1.5 ui-sans-serif,system-ui;color:var(--muted);letter-spacing:.18em;text-transform:uppercase;margin-top:4px}.header{height:76px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 max(5%,calc((100% - 1200px)/2))}.header .back{font-size:12px;color:var(--muted);text-decoration:none}.header .back:hover{color:var(--olive-dark)}main{min-height:calc(100vh - 167px);display:grid;place-items:center;padding:42px 18px}.card{width:min(450px,100%);background:white;border:1px solid var(--line);padding:36px 40px;box-shadow:0 18px 55px #28281f0c}.eyebrow{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--olive-dark);font-weight:650}.card h1{font:400 36px/1.12 Georgia,serif;margin:11px 0 7px}.intro{color:var(--muted);font-size:13px;margin:0 0 24px}.field{margin:15px 0}.field label{display:block;font-size:11px;margin-bottom:7px}.field input{width:100%;border:1px solid var(--line);padding:12px 13px;outline:none;background:#fff;font:13px inherit}.field input:focus{border-color:var(--olive);box-shadow:0 0 0 3px #68745b18}.submit{width:100%;background:var(--ink);color:white;border:0;padding:13px;font-size:13px;margin-top:6px;cursor:pointer}.submit:hover{background:var(--olive-dark)}.message{padding:11px 13px;margin:0 0 16px;font-size:12px}.error{background:#f7e9e6;color:#8d4238}.success{background:#eef1e9;color:#4d5b42}.footlink{text-align:center;margin:17px 0 0;font-size:12px}.footlink a,.message a{color:var(--olive-dark)}.hint{font-size:10px;color:var(--muted);margin:13px 0 0}.footer{text-align:center;padding:17px;color:var(--muted);font-size:10px;border-top:1px solid var(--line)}@media(max-width:520px){.card{padding:29px 23px}.header{height:68px}.card h1{font-size:32px}}
</style>
</head>
<body>
<div class="topline">Thoughtful style, easy shopping.</div>
<header class="header"><a class="brand" href="clothing-shop-interface.php">THREAD &amp; FORM<small>Clothing shop</small></a><a class="back" href="login.php">← Back to sign in</a></header>
<main><section class="card" aria-labelledby="heading">
  <span class="eyebrow">Customer account</span>
  <h1 id="heading"><?= $created ? 'You are all set.' : 'Create your account' ?></h1>
  <p class="intro"><?= $created ? 'Your active customer account has been created.' : 'Create an account to shop the collection and place orders.' ?></p>
  <?php if ($error !== ''): ?><div class="message error" role="alert"><?=h($error)?></div><?php endif; ?>
  <?php if ($created): ?>
    <div class="message success" role="status">Registration complete. You can now sign in with your email and password.</div>
    <a class="submit" style="display:block;text-align:center;text-decoration:none" href="login.php">Continue to sign in</a>
  <?php else: ?>
    <form method="post" autocomplete="on">
      <input type="hidden" name="csrf_token" value="<?=h((string)$_SESSION['register_csrf'])?>">
      <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254" value="<?=h($email)?>" placeholder="you@example.com"></div>
      <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="6" required placeholder="At least 6 characters"></div>
      <div class="field"><label for="password_confirmation">Confirm password</label><input id="password_confirmation" name="password_confirmation" type="password" autocomplete="new-password" minlength="6" required placeholder="Enter your password again"></div>
      <button class="submit" type="submit">Create account</button>
    </form>
    <p class="hint">Passwords are stored securely as a hash. New accounts receive the Customer role.</p>
    <p class="footlink">Already have an account? <a href="login.php">Sign in</a></p>
  <?php endif; ?>
</section></main>
<footer class="footer">© <?=date('Y')?> Thread &amp; Form · Clothing Shop Management System</footer>
</body>
</html>
