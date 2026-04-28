/**
 * Seeds localStorage bypass keys in a running Chrome tab via CDP.
 * Uses only Node built-ins (net, http) — no ws/puppeteer required.
 *
 * Usage: node seed-localstorage.mjs <cdp-port> <url>
 */
import http from "http";
import net from "net";
import crypto from "crypto";

const [,, cdpPort, targetUrl] = process.argv;

// 1. Get debugger URL from Chrome
async function getDebuggerUrl(port) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:${port}/json/list`, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try {
          const targets = JSON.parse(data);
          const t = targets.find(t => t.type === "page") || targets[0];
          resolve(t?.webSocketDebuggerUrl);
        } catch(e) { reject(e); }
      });
    }).on("error", reject);
  });
}

// 2. Minimal WebSocket client using only net module
function wsSend(socket, message) {
  const data = Buffer.from(JSON.stringify(message));
  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + text frame
    header[1] = 0x80 | len; // MASK bit + length
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  const mask = crypto.randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = data[i] ^ mask[i % 4];
  socket.write(Buffer.concat([header, mask, masked]));
}

async function cdpEval(wsUrl, expression) {
  return new Promise((resolve, reject) => {
    const url = new URL(wsUrl);
    const key = crypto.randomBytes(16).toString("base64");

    const socket = net.createConnection({ host: url.hostname, port: Number(url.port) || 80 }, () => {
      // Send HTTP upgrade request
      socket.write(
        `GET ${url.pathname}${url.search} HTTP/1.1\r\n` +
        `Host: ${url.host}\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`
      );
    });

    let upgraded = false;
    let buf = Buffer.alloc(0);
    let msgId = 1;
    let done = false;

    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (!upgraded) {
        const str = buf.toString();
        if (str.includes("101")) {
          upgraded = true;
          // Send Runtime.evaluate
          wsSend(socket, {
            id: msgId++,
            method: "Runtime.evaluate",
            params: {
              expression: [
                "localStorage.setItem('FIXOPS_VISUAL_VERIFY','1')",
                "localStorage.setItem('aldeci.authStrategy','token')",
                "localStorage.setItem('aldeci.authToken','aldeci-demo-key')",
                "localStorage.setItem('aldeci.authUser',JSON.stringify({id:'dev-user',email:'dev@verify',first_name:'Dev',last_name:'Verify',role:'admin',department:'platform'}))",
                "localStorage.setItem('aldeci.orgId','juice-shop-corp')",
              ].join(";"),
              returnByValue: true,
            }
          });
        }
      } else if (!done) {
        // Parse WebSocket frame (simplified — assumes single frame response)
        if (buf.length > 2) {
          const fin = (buf[0] & 0x80) !== 0;
          const opcode = buf[0] & 0x0f;
          const masked = (buf[1] & 0x80) !== 0;
          let payloadLen = buf[1] & 0x7f;
          let offset = 2;
          if (payloadLen === 126) { payloadLen = buf.readUInt16BE(2); offset = 4; }
          else if (payloadLen === 127) { payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
          if (masked) offset += 4;
          if (buf.length >= offset + payloadLen) {
            done = true;
            socket.destroy();
            resolve("ok");
          }
        }
      }
    });

    socket.on("error", reject);
    setTimeout(() => { if (!done) { socket.destroy(); resolve("timeout"); } }, 5000);
  });
}

async function main() {
  try {
    const wsUrl = await getDebuggerUrl(Number(cdpPort));
    if (!wsUrl) { console.error("No debugger URL found"); process.exit(1); }
    await cdpEval(wsUrl, "");
    console.log("localStorage seeded OK");
    process.exit(0);
  } catch(e) {
    console.error("Seed failed:", e.message);
    process.exit(1);
  }
}

main();
