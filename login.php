<?php
/**
 * Clothing Shop Management System ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â login page
 *
 * Database configuration (optional environment variables):
 * CLOTHING_DB_HOST, CLOTHING_DB_NAME, CLOTHING_DB_USER, CLOTHING_DB_PASSWORD
 * Defaults are for a local XAMPP install: localhost / clothing_shop / root / blank password.
 *
 * Expected MySQL table:
 * users(id, email, password_hash, role, status)
 * password_hash must contain a PHP password_hash() value; status must be "Active"
 * and role must be "Admin" or "Customer".
 */
declare(strict_types=1);

$isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'secure' => $isHttps,
    'samesite' => 'Lax',
]);
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

if (empty($_SESSION['login_csrf'])) {
    $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
}

$error = '';
$notice = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    $postedToken = (string)($_POST['csrf_token'] ?? '');
    if (hash_equals((string)$_SESSION['login_csrf'], $postedToken)) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $cookie = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $cookie['path'], $cookie['domain'], $cookie['secure'], $cookie['httponly']);
        }
        session_destroy();
        session_start();
        $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
        $notice = 'You have been signed out.';
    } else {
        $error = 'Your session expired. Refresh the page and try again.';
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $postedToken = (string)($_POST['csrf_token'] ?? '');
    $email = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if (!hash_equals((string)$_SESSION['login_csrf'], $postedToken)) {
        $error = 'Your session expired. Refresh the page and try again.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        $error = 'Enter a valid email address and password.';
    } else {
        try {
            require __DIR__ . '/connection.php';
            $pdo = $conn;
            $statement = $pdo->prepare('SELECT id, email, password_hash, role, status FROM users WHERE email = :email LIMIT 1');
            $statement->execute(['email' => $email]);
            $account = $statement->fetch();

            if (!$account || !password_verify($password, (string)$account['password_hash']) || strcasecmp((string)$account['status'], 'Active') !== 0) {
                $error = 'The email or password is incorrect, or the account is inactive.';
            } elseif (!in_array((string)$account['role'], ['Admin', 'Customer'], true)) {
                $error = 'This account does not have a valid shop role. Contact the administrator.';
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int)$account['id'];
                $_SESSION['user_email'] = (string)$account['email'];
                $_SESSION['user_role'] = (string)$account['role'];
                $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
                header('Location: clothing-shop-interface.php');
                exit;
            }
        } catch (PDOException $exception) {
            // Keep database details out of the page; inspect the PHP/server log when configuring MySQL.
            error_log('Clothing shop login database error: ' . $exception->getMessage());
            $error = 'Login is temporarily unavailable. Check the database connection and try again.';
        }
    }
}

$isLoggedIn = isset($_SESSION['user_id'], $_SESSION['user_role']);
function h(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in Ãƒâ€šÃ‚Â· Thread &amp; Form</title>
<style>
:root{--ink:#24241f;--muted:#77776e;--paper:#faf9f6;--white:#fff;--line:#e9e7e0;--olive:#68745b;--olive-dark:#4d5b42;--sand:#eee9df}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.topline{background:#34372f;color:#f8f7f2;text-align:center;padding:9px 14px;font-size:11px;letter-spacing:.09em}.brand{font:600 20px Georgia,serif;letter-spacing:.05em;color:inherit;text-decoration:none}.brand small{display:block;font:10px/1.5 ui-sans-serif,system-ui;color:var(--muted);letter-spacing:.18em;text-transform:uppercase;margin-top:4px}.header{height:76px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 max(5%,calc((100% - 1200px)/2))}.header a.back{font-size:12px;color:var(--muted);text-decoration:none}.header a.back:hover{color:var(--olive-dark)}main{min-height:calc(100vh - 167px);display:grid;place-items:center;padding:46px 18px}.card{width:min(440px,100%);background:white;border:1px solid var(--line);padding:38px 40px;box-shadow:0 18px 55px #28281f0c}.eyebrow{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--olive-dark);font-weight:650}.card h1{font:400 36px/1.12 Georgia,serif;margin:11px 0 7px}.intro{color:var(--muted);font-size:13px;margin:0 0 26px}.field{margin:17px 0}.field label{display:block;font-size:11px;margin-bottom:7px}.field input{width:100%;border:1px solid var(--line);padding:12px 13px;outline:none;background:#fff;font:13px inherit}.field input:focus{border-color:var(--olive);box-shadow:0 0 0 3px #68745b18}.submit{width:100%;background:var(--ink);color:white;border:0;padding:13px;font-size:13px;margin-top:5px;cursor:pointer}.submit:hover{background:var(--olive-dark)}.message{padding:11px 13px;margin:0 0 17px;font-size:12px}.error{background:#f7e9e6;color:#8d4238}.notice{background:#eef1e9;color:#4d5b42}.hint{font-size:10px;color:var(--muted);margin:15px 0 0}.signed{background:#f5f5f0;padding:16px;font-size:13px;margin:20px 0}.signed strong{display:block;font:400 21px Georgia,serif;margin:5px 0}.signed span{color:var(--muted)}.footer{text-align:center;padding:17px;color:var(--muted);font-size:10px;border-top:1px solid var(--line)}@media(max-width:520px){.card{padding:30px 24px}.header{height:68px}.card h1{font-size:32px}}
</style>
</head>
<body>
<div class="topline">Thoughtful style, easy shopping.</div>
<header class="header"><a class="brand" href="clothing-shop-interface.php">THREAD &amp; FORM<small>Clothing shop</small></a><a class="back" href="clothing-shop-interface.php">← Back to shop</a></header>
<main><section class="card" aria-labelledby="heading">
  <span class="eyebrow"><?= $isLoggedIn ? 'Your account' : 'Customer account' ?></span>
  <h1 id="heading"><?= $isLoggedIn ? 'Welcome back.' : 'Sign in' ?></h1>
  <p class="intro"><?= $isLoggedIn ? 'You are signed in to Thread & Form.' : 'Enter your account details to continue shopping.' ?></p>
  <?php if ($error !== ''): ?><div class="message error" role="alert"><?=h($error)?></div><?php endif; ?>
  <?php if ($notice !== ''): ?><div class="message notice" role="status"><?=h($notice)?></div><?php endif; ?>
  <?php if ($isLoggedIn): ?>
    <div class="signed"><span>Signed in as</span><strong><?=h((string)$_SESSION['user_email'])?></strong><span>Account role: <?=h((string)$_SESSION['user_role'])?></span></div>
    <form method="post"><input type="hidden" name="action" value="logout"><input type="hidden" name="csrf_token" value="<?=h((string)$_SESSION['login_csrf'])?>"><button class="submit" type="submit">Sign out</button></form>
  <?php else: ?>
    <form method="post" autocomplete="on">
      <input type="hidden" name="action" value="login"><input type="hidden" name="csrf_token" value="<?=h((string)$_SESSION['login_csrf'])?>">
      <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254" value="<?=h((string)($_POST['email'] ?? ''))?>" placeholder="you@example.com"></div>
      <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required minlength="6" placeholder="Enter your password"></div>
      <button class="submit" type="submit">Sign in</button>
    </form>
    <p style="text-align:center;margin:16px 0 0;font-size:12px">New to Thread &amp; Form? <a href="registration.php" style="color:var(--olive-dark)">Create an account</a></p>
    <p class="hint">Your account must be active. Passwords are checked against their stored hash.</p>
  <?php endif; ?>
</section></main>
<footer class="footer"> <?=date('Y')?> Thread &amp; Form Clothing Shop Management System</footer>
</body>
</html>
