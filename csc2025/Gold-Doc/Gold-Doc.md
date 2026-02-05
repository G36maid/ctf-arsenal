2025 金盾獎 教學題 Gold Doc

登入系統 & 安裝元件

在登入畫面的 HTML 原始碼可以看到 user1 的帳號密碼。以此帳號可以登入系統。

登入後會發現缺少本機元件，需下載安裝，元件以 docker 包裝，可以直接 docker compose up 啟動，唯須注意
docker-compose.yaml 內的 GOLDDOC_AGENT_ALLOWED_ORIGIN 需要設成這個系統的網址，否則會無法跟元
件連線。

啟動元件後若重新整理網頁，可能仍然會看到元件無法連線，此時可以打開瀏覽器的開發者工具，應該會看到如下:
ERR_CERT_AUTHORITY_INVALID 錯誤。

此時對該錯誤的 request 點兩下，或直接開新分頁瀏覽: https://127.0.0.1:8443/ping
會看到憑證錯誤畫面:

此時只須點選 “繼續前往”

看到這個 Method Not Allowed 畫面即可關閉分頁，回到原本的網頁重新整理

元件正常啟動後重新整理系統畫面會看到如下圖所示，本機元件狀態會顯示 json 結果。

漏洞: XSS

測試建立文件功能，在標題跟內文都嘗試注入 HTML 語法。

發現標題欄位有 XSS 漏洞。

漏洞: Path Traversal

接下來回頭檢視下載元件的網址，嘗試在網址測試是否存在 Path Traversal 漏洞。經過一連串測試與觀察會發現可
以用 %25252f 三次的 URL Encode 做到 Path Traversal。

取得 Path Traversal 漏洞後可以嘗試讀取 apache Config，會發現 webroot 在 /var/www/html/public。接下來嘗試讀
取 index.html，發現檔案不存在，但是當我們連上系統時網址是 http://x.x.x.x/ ，所以代表 apache 應該有設定一些規
則，而這些規則沒出現在 /etc/apache2/sites-available/000-default.conf，那有可能是透過 .htaccess 設定的，所以可
以嘗試讀取 .htaccess。

讀到 .htaccess 後會發現許多 php 檔案的路徑，至此已經可以透過 PHP 檔案內 require、include 等引用資訊逐步將
整個網站的 PHP 原始碼讀出來。

讀取 docker-entrypoint.sh 檔案也可以發現 db_init.php，裡面有 admin 的密碼，至此可以取得 admin 帳密。

系統與元件互動方式

觀察瀏覽器發出的請求紀錄，會發現如果系統要跟元件互動，流程是: 前端向後端發送請求->後端驗證請求->後端
產出元件 Payload 並簽章->前端將 Payload 送給元件。

從先前漏洞取得的 PHP 原始碼中可以在 agent_service.php 檔案找到後端用來簽章元件 Payload 的 Private Key。

agent_service.php

使用 Path Traversal 漏洞將 Private Key 讀出。

完整利用鏈

觀察網頁與元件互動行為會發現有一個 download 功能，該功能可以把檔案下載到使用者電腦的特定資料夾。在這
個功能的 payload 裡面有一個 target_dir 可以指定資料夾的參數，該參數從後端產生時永遠只會是空字串，因此我
們沒辦法從後端產生一個可以使用 download 功能在使用者電腦任意寫入的 Payload。

但是我們透過 Path Traversal 已經取得後端用來簽 Payload 的 Private Key，所以我們可以自行產生任何 Payload
並自行用該 Private Key 簽章。

接下來需要思考有了在使用者電腦任意寫入的方式後，要寫入什麼檔案?
觀察網頁介面可以發現有一個重新載入元件的功能，通過逆向元件或是猜測，可以發現該功能會讓元件重新讀取
Config 檔案。

所以我們可以將使用者電腦內元件的 Config 檔案 (/etc/golddoc-agent/config.json) 內容覆寫，將
user_public_key_path 改成 /etc/golddoc-agent/user_private.pem，然後將元件重新載入，接著透過 ping 會回傳使
用者 Public Key 的功能取得使用者的 Private Key。

你可以透過隨本教學文件附帶的 generate_agent_request.py 產生已簽章的 download / reload / ping 等操作的
Payload，並使用 XSS 漏洞使 Admin 觸發 Admin 電腦上的元件，並取得 Admin 的 Private Key。

透過腳本產生能觸發元件 download 的 XSS payload。
python3 generate_agent_request.py --key ./web_private.pem --op download --target
/etc/golddoc-agent/config.json --content-file ./config.json
請自行將 web_private.pem 換成儲存後端用來簽章的 Private Key 的路徑。將 config.json 替換成已修改過的 config
的路徑。

透過腳本產生能觸發元件 reload 的 XSS payload。
python3 generate_agent_request.py --key ./web_private.pem --op reload

透過腳本產生能觸發元件 ping 的 XSS payload。
python3 generate_agent_request.py --key ./web_private.pem --op ping

你可以使用 fetch().then() 來串接完整操作，並避免 XSS 影響到自己的元件。
如下圖所示，首先確認身分不是 user1 (避免觸發自己的元件) -> 觸發 download 將 config.json 覆寫 -> 觸發 reload
使元件重新載入，最後執行 ping，並將結果傳出去。(這邊使用 request bin 接收)

這邊可以使用教學文件隨附的 exp_template.txt，將裡面的 <Download Payload>、<Reload Payload>、<Ping
Payload> 等 Tag 替換成上一步驟使用腳本產生的 Payload (Agent Request 的 Payload)。並將 <Request Bin URL>
等替換成 Request Bin 產生的網址，或是自行架設的 Web Server。

可以發現 Admin 的 Private Key 被傳送出來。

接著使用先前取得的 Admin 帳號密碼登入後可以發現管理員可以上傳元件檔案。但是檔案需要簽章。

根據說明，我們可以使用網頁提供的 sign_agent_file.sh 以及我們取得的 admin 的 Private Key 進行簽章。
製作一個 readflag.php 檔案，並簽章上傳。

可發現成功上傳，但是此時的 PHP 檔案不在可以直接從網頁存取執行的地方。

觀察上傳元件的程式碼可以發現它使用 full_path 參數來取得檔案名稱，此參數可以插入 ../ 來達到 Path Traversal。

透過上傳元件的 Path Traversal 我們可以將 readflag.php 上傳到可直接存取的位置。

最後存取 readflag.php 就會取得 Flag !!