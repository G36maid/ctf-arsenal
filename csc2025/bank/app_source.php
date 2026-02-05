<?php
if (strpos($_SERVER['HTTP_USER_AGENT'], 'MSIE') === false &&
    strpos($_SERVER['HTTP_USER_AGENT'], 'Trident') === false) {
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div id="content">
        <img style="width: 50%;" src="/static/logo.png" alt="Bank Logo">
        <div>
            <h2>本行不支援您使用的瀏覽器。請使用最新的Ｉｎｔｅｒｎｅｔ　Ｅｘｐｌｏｒｅｒ以獲得最佳的瀏覽體驗。</h2>
        </div>
    </div>
</body>
</html>
<?php
    die();
}

function redirect_back(): void {
    header('Location: /', true, 302);
    die;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' ||
    !isset($_POST['userid'])  || !is_string($_POST['userid']) ||
    !isset($_POST['passwd'])  || !is_string($_POST['passwd']) ||
    !isset($_POST['captcha']) || !is_string($_POST['captcha'])) {
    redirect_back();
}

$userid = $_POST['userid'];
$passwd = $_POST['passwd'];
$captcha = $_POST['captcha'];

if ($userid === '' || $passwd === '' || $captcha !== '田メ５Ѭꙮ҆¿') {
    redirect_back();
}

try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/users.sqlite3', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    $stmt = $pdo->prepare('SELECT * FROM users WHERE userid = :uid LIMIT 1');
    $stmt->execute([':uid' => $userid]);
    $user_data = $stmt->fetch();

    if (!$user_data || empty($user_data['passwd'])) {
        redirect_back();
    }

    if (!password_verify($passwd, $user_data['passwd'])) {
        redirect_back();
    }
} catch (Throwable $e) {
    redirect_back();
}

if (!isset($_ENV['TEAM_ID']) || $_ENV['TEAM_ID'] === '') {
    http_response_code(500);
    echo('FATAL ERROR: Could not determine team ID; please contact staff');
    die();
}

$pdf_file = '/var/run/bills/' . $_ENV['TEAM_ID']  . '.pdf';
if (!file_exists($pdf_file)) {
    http_response_code(500);
    echo('FATAL ERROR: Could not find the team\'s PDF file; please contact staff');
    die();
}

?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div id="content">
        <img style="width: 50%;" src="/static/logo.png" alt="Bank Logo">
        <h1>使用者&#xFFFD;<?= $user_data['userid'] ?></h1>
        <div>
            <h2>活期存款</h2>
            TWD$ <?= $user_data['balance'] ?>
        </div>
        <div>
            <h2>負債</h2>
            TWD$ <?= $user_data['debt'] ?>
        </div>
        <div>
            <h2>網路轉帳</h2>
            <form>
                <div>
                    <label for="account">轉入帳號</label>
                    <br>
                    <input type="text" id="account" name="account" required />
                </div>
                <div>
                    <label for="amount">金額（新臺幣）</label>
                    <br>
                    <input type="text" id="amount" name="amount" required />
                </div>
                <div>
                    <label for="passwd">轉帳密碼</label>
                    <br>
                    <input type="password" id="passwd" name="passwd" required />
                </div>
                <button type="submit" disabled>確定</button>
            </form>
            <p>
                本行線上轉帳功能正在維護中，如有需求可至全國分行臨櫃匯款。
            </p>
        </div>
        <div>
            <h2>下載專區</h2>
            <a target="_blank" href="data:application/pdf;base64,<?= base64_encode(file_get_contents($pdf_file)) ?>">下載最新一期信用卡帳單</a>
            <p>
                注意：為了維護您的隱私權，本期帳單需要輸入您的身份證字號後開啟。
            </p>
        </div>
        <div id="footer">
            &copy; 海貓銀行 Copyright Seacat Bank. All Rights Reserved.
        </div>
    </div>
</body>
</html>
