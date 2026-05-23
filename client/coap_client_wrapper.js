import coap from 'coap';
import { execSync } from 'child_process';

const isWindows = process.platform === 'win32';
const prefix = isWindows ? 'wsl ' : '';

/**
 * Perform a CoAP GET request.
 * @param {string} url - CoAP URL (e.g., coap://127.0.0.1:5683/rsa/key or coaps://127.0.0.1:5684/rsa/key)
 * @param {boolean} secure - Whether to use DTLS (CoAPs)
 * @param {string} [user] - PSK Identity (required for CoAPs)
 * @param {string} [key] - PSK Secret Key (required for CoAPs)
 * @returns {Promise<any>} - Parsed JSON response
 */
export function coapGet(url, secure = false, user = '', key = '') {
  return new Promise((resolve, reject) => {
    if (secure || url.startsWith('coaps://')) {
      // Use coap-client-openssl inside WSL for secure DTLS with PSK
      try {
        console.log(`  [CoAPs GET] Calling coap-client-openssl for: ${url}`);
        const command = `${prefix}coap-client-openssl -m get -u "${user}" -k "${key}" "${url}"`;
        const stdout = execSync(command).toString();
        
        // coap-client outputs some debug lines first, the response body is usually the last lines or single line
        const responseBody = cleanCoapClientOutput(stdout);
        resolve(JSON.parse(responseBody));
      } catch (err) {
        reject(new Error(`WSL coap-client error: ${err.message}`));
      }
    } else {
      // Use standard Node.js 'coap' library for plain CoAP
      console.log(`  [CoAP GET] Calling Node.js coap library for: ${url}`);
      const parsedUrl = new URL(url);
      const req = coap.request({
        host: parsedUrl.hostname,
        port: parsedUrl.port ? parseInt(parsedUrl.port) : 5683,
        pathname: parsedUrl.pathname,
        method: 'GET'
      });

      req.on('response', (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            resolve(body);
          }
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    }
  });
}

/**
 * Perform a CoAP POST request.
 * @param {string} url - CoAP URL (e.g., coap://127.0.0.1:5683/rsa/sign)
 * @param {object} payload - JSON object payload to send
 * @param {boolean} secure - Whether to use DTLS (CoAPs)
 * @param {string} [user] - PSK Identity (required for CoAPs)
 * @param {string} [key] - PSK Secret Key (required for CoAPs)
 * @returns {Promise<any>} - Parsed JSON response
 */
export function coapPost(url, payload, secure = false, user = '', key = '') {
  return new Promise((resolve, reject) => {
    const payloadStr = JSON.stringify(payload);

    if (secure || url.startsWith('coaps://')) {
      // Use coap-client-openssl inside WSL for secure DTLS with PSK
      try {
        console.log(`  [CoAPs POST] Calling coap-client-openssl for: ${url}`);
        // Escape quotes in payload for shell execution
        const escapedPayload = payloadStr.replace(/"/g, '\\"');
        const command = `${prefix}coap-client-openssl -m post -u "${user}" -k "${key}" -t application/json -e "${escapedPayload}" "${url}"`;
        const stdout = execSync(command).toString();
        
        const responseBody = cleanCoapClientOutput(stdout);
        resolve(JSON.parse(responseBody));
      } catch (err) {
        reject(new Error(`WSL coap-client error: ${err.message}`));
      }
    } else {
      // Use standard Node.js 'coap' library for plain CoAP
      console.log(`  [CoAP POST] Calling Node.js coap library for: ${url}`);
      const parsedUrl = new URL(url);
      const req = coap.request({
        host: parsedUrl.hostname,
        port: parsedUrl.port ? parseInt(parsedUrl.port) : 5683,
        pathname: parsedUrl.pathname,
        method: 'POST',
        options: {
          'Content-Format': 'application/json'
        }
      });

      req.on('response', (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            resolve(body);
          }
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.write(payloadStr);
      req.end();
    }
  });
}

/**
 * Helper function to extract response payload from coap-client output.
 * coap-client outputs headers and info lines before the actual payload.
 */
function cleanCoapClientOutput(output) {
  const lines = output.split('\n');
  let jsonStarted = false;
  let jsonStr = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('{') || jsonStarted) {
      jsonStarted = true;
      jsonStr += trimmed;
      if (trimmed.endsWith('}')) {
        break;
      }
    }
  }

  if (jsonStr) {
    return jsonStr;
  }
  
  // Fallback: search for first '{' and last '}'
  const start = output.indexOf('{');
  const end = output.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    return output.substring(start, end + 1);
  }

  return output.trim();
}
