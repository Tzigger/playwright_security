const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  const query = url.parse(req.url, true).query;
  const input = query.q || '';

  // VULNERABILITY: Simulate SQLi SLEEP
  // If input contains "SLEEP(2)", we delay response by 2000ms
  if (input.includes('SLEEP(2)')) {
    console.log(`[Server] Detected attack payload: ${input}. Sleeping...`);
    setTimeout(() => {
      res.writeHead(200);
      res.end('Vulnerable Content');
    }, 2000);
  } else {
    // Normal response
    res.writeHead(200);
    res.end('Normal Content');
  }
});

server.listen(8081, () => console.log('Vulnerable Server running on port 8081'));