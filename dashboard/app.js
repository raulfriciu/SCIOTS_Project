// ==========================================================================
// SCIOTS Premium Dashboard Logic (Vanilla ES6)
// ==========================================================================

let activeScheme = 'paillier';
let isSecure = false;
let paillierBuffer = [];
let statusInterval = null;
let logsInterval = null;

// DOM Elements
const secureModeToggle = document.getElementById('secureModeToggle');
const tabPaillier = document.getElementById('tabPaillier');
const tabRSA = document.getElementById('tabRSA');

const statusServerE = document.getElementById('statusServerE');
const statusAggregator = document.getElementById('statusAggregator');
const statusProxy = document.getElementById('statusProxy');

const coapPortLabel = document.getElementById('coapPortLabel');
const httpPortLabel = document.getElementById('httpPortLabel');

const bufferCount = document.getElementById('bufferCount');
const ciphertextGrid = document.getElementById('ciphertextGrid');
const btnAggregate = document.getElementById('btnAggregate');
const paillierFormulaBox = document.getElementById('paillierFormulaBox');
const paillierFormulaDetails = document.getElementById('paillierFormulaDetails');

const utilityReceiveBox = document.getElementById('utilityReceiveBox');
const paillierCombinedLock = document.getElementById('paillierCombinedLock');
const utilityReceiveTitle = document.getElementById('utilityReceiveTitle');
const utilityReceiveDesc = document.getElementById('utilityReceiveDesc');
const btnDecrypt = document.getElementById('btnDecrypt');
const ledgerBox = document.getElementById('ledgerBox');
const ledgerConsumoVal = document.getElementById('ledgerConsumoVal');

const rsaVisualIcon = document.getElementById('rsaVisualIcon');
const rsaAggStatusTitle = document.getElementById('rsaAggStatusTitle');
const rsaAggStatusDesc = document.getElementById('rsaAggStatusDesc');
const rsaStepsBox = document.getElementById('rsaStepsBox');
const rsaStep1 = document.getElementById('rsaStep1');
const rsaStep2 = document.getElementById('rsaStep2');
const rsaStep3 = document.getElementById('rsaStep3');
const rsaStep4 = document.getElementById('rsaStep4');

const rsaReceiveBox = document.getElementById('rsaReceiveBox');
const rsaLockIllustration = document.getElementById('rsaLockIllustration');
const rsaReceiveTitle = document.getElementById('rsaReceiveTitle');
const rsaReceiveDesc = document.getElementById('rsaReceiveDesc');
const rsaVerifyBox = document.getElementById('rsaVerifyBox');
const rsaOriginalVal = document.getElementById('rsaOriginalVal');
const rsaFinalSigVal = document.getElementById('rsaFinalSigVal');
const rsaVerificationVal = document.getElementById('rsaVerificationVal');
const rsaVerificationBadge = document.getElementById('rsaVerificationBadge');

const logsTerminal = document.getElementById('logsTerminal');
const pubKeyVal = document.getElementById('pubKeyVal');

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  fetchInitialKeys();
  startPolling();
  
  // Custom terminal initial lines
  appendLocalLog('SISTEMA', 'system', 'Consola del Dashboard lista. Conectando con los microservicios...');
});

// Event Listeners Setup
function setupEventListeners() {
  // Protocol Toggle
  secureModeToggle.addEventListener('change', (e) => {
    isSecure = e.target.checked;
    updateProtocolPorts();
    fetchInitialKeys();
    appendLocalLog('SISTEMA', 'system', `Modo de seguridad cambiado a: ${isSecure ? 'CoAPs (DTLS + PSK)' : 'CoAP (Plano)'}`);
  });

  // Tab Switchers
  tabPaillier.addEventListener('click', () => {
    switchTab('paillier');
  });

  tabRSA.addEventListener('click', () => {
    switchTab('rsa');
  });
}

function updateProtocolPorts() {
  if (isSecure) {
    coapPortLabel.textContent = activeScheme === 'paillier' ? 'Puerto UDP 5686 (DTLS)' : 'Puerto UDP 5684 (DTLS)';
  } else {
    coapPortLabel.textContent = activeScheme === 'paillier' ? 'Puerto UDP 5685' : 'Puerto UDP 5683';
  }
  httpPortLabel.textContent = activeScheme === 'paillier' ? 'Puerto TCP 4000' : 'Puerto TCP 3000';
}

function switchTab(scheme) {
  activeScheme = scheme;
  
  if (scheme === 'paillier') {
    tabPaillier.classList.add('active');
    tabRSA.classList.remove('active');
    
    // Toggle displays
    document.querySelectorAll('.paillier-only').forEach(el => el.classList.remove('hidden'));
    document.querySelectorAll('.rsa-only').forEach(el => el.classList.add('hidden'));
  } else {
    tabPaillier.classList.remove('active');
    tabRSA.classList.add('active');
    
    // Toggle displays
    document.querySelectorAll('.paillier-only').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.rsa-only').forEach(el => el.classList.remove('hidden'));
  }
  
  updateProtocolPorts();
  fetchInitialKeys();
  appendLocalLog('SISTEMA', 'system', `Esquema de demostración cambiado a: ${scheme.toUpperCase()}`);
}

// Start polling API status and system logs
function startPolling() {
  // Poll Status every 2.5 seconds
  checkSystemStatus();
  statusInterval = setInterval(checkSystemStatus, 2500);

  // Poll Logs every 1 second
  fetchSystemLogs();
  logsInterval = setInterval(fetchSystemLogs, 1000);
}

// Check system statuses (Active ServerE, Aggregator, Proxy)
async function checkSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    
    updateIndicator(statusServerE, data.serverE);
    updateIndicator(statusAggregator, data.aggregator);
    updateIndicator(statusProxy, data.proxy);
  } catch (err) {
    updateIndicator(statusServerE, false);
    updateIndicator(statusAggregator, false);
    updateIndicator(statusProxy, false);
  }
}

function updateIndicator(element, active) {
  if (active) {
    element.classList.add('active');
  } else {
    element.classList.remove('active');
  }
}

// Fetch Initial Public Keys from server to display in Vault
async function fetchInitialKeys() {
  pubKeyVal.textContent = 'Cargando...';
  const protocol = isSecure ? 'coaps' : 'coap';
  const port = isSecure ? 5684 : 5683;
  const endpoint = activeScheme === 'paillier' ? '/paillier/key' : '/rsa/key';
  const url = `${protocol}://127.0.0.1:${port}${endpoint}`;

  try {
    // We can hit the local endpoints of our UI bridge to fetch keys or let it load
    // For visual aesthetics, we query the server which handles CoAP calls
    const res = await fetch(activeScheme === 'paillier' ? '/api/send-paillier' : '/api/send-rsa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meterId: 1, value: 0, isSecure }) // Value 0 is just to trigger public key fetch
    });
    
    const data = await res.json();
    if (data.success && data.details) {
      pubKeyVal.textContent = `n = ${data.details.n.substring(0, 20)}...`;
      pubKeyVal.title = `n = ${data.details.n}`;
    } else {
      pubKeyVal.textContent = 'Error al conectar';
    }
  } catch (err) {
    pubKeyVal.textContent = 'Fuera de línea';
  }
}

// Fetch captured system logs from the server
async function fetchSystemLogs() {
  try {
    const res = await fetch('/api/logs');
    const logs = await res.json();
    
    // Clear logs body
    logsTerminal.innerHTML = '';
    
    if (logs.length === 0) {
      appendLocalLog('SISTEMA', 'system', 'Consola limpia. Listo para realizar transacciones.');
      return;
    }

    logs.forEach(log => {
      const logLine = document.createElement('div');
      logLine.className = `log-line log-${log.type.toLowerCase()}`;
      logLine.textContent = `[${log.timestamp}] [${log.source}] [${log.type}] ${log.message}`;
      
      if (log.details) {
        const detailsLine = document.createElement('div');
        detailsLine.className = 'log-line log-system';
        detailsLine.style.paddingLeft = '1.5rem';
        detailsLine.textContent = `⤷ Detalle: ${JSON.stringify(log.details)}`;
        logLine.appendChild(detailsLine);
      }
      
      logsTerminal.appendChild(logLine);
    });

    // Auto-scroll to bottom of terminal
    logsTerminal.scrollTop = logsTerminal.scrollHeight;
  } catch (err) {
    // Ignore log fetch errors during loading
  }
}

// Append log internally for local events
function appendLocalLog(source, type, message) {
  const timestamp = new Date().toLocaleTimeString();
  const logLine = document.createElement('div');
  logLine.className = `log-line log-${type}`;
  logLine.textContent = `[${timestamp}] [${source}] [${type.toUpperCase()}] ${message}`;
  logsTerminal.appendChild(logLine);
  logsTerminal.scrollTop = logsTerminal.scrollHeight;
}

// Clear logs action
async function clearLogs() {
  try {
    await fetch('/api/logs/clear', { method: 'POST' });
    fetchSystemLogs();
  } catch (err) {
    appendLocalLog('DASHBOARD', 'error', 'Error al borrar logs del servidor.');
  }
}

// Play CoAP to HTTP Translation Particle Animation
function animateNetworkFlow() {
  const container = document.getElementById('particles');
  container.innerHTML = ''; // Clear previous

  const packet = document.createElement('div');
  packet.className = 'packet-dot coap-packet';
  container.appendChild(packet);

  // Phase 1: Animate particle from 0% (CoAP Client) to 50% (Proxy node)
  let position = 0;
  const interval = setInterval(() => {
    position += 2;
    packet.style.left = `${position}%`;

    // Phase 2: Convert from CoAP (Blue) to HTTP (Green) at Proxy Node (50%)
    if (position >= 48 && position <= 52) {
      packet.className = 'packet-dot http-packet';
    }

    // Phase 3: Arrive at destination (100%)
    if (position >= 100) {
      clearInterval(interval);
      setTimeout(() => {
        packet.remove();
      }, 500);
    }
  }, 20);
}

// Meter Action: Submit readings
async function sendMeterData(meterId, scheme) {
  const meterCard = document.getElementById(`meter${meterId}`);
  const btn = meterCard.querySelector('.btn-send');
  
  let val = 0;
  if (scheme === 'paillier') {
    val = document.getElementById(`valMeter${meterId}`).value;
  } else {
    val = document.getElementById(`msgMeter${meterId}`).value;
  }

  if (!val || val <= 0) {
    alert('Por favor ingrese un valor válido.');
    return;
  }

  // Visual disable loading state
  btn.disabled = true;
  meterCard.style.boxShadow = `0 0 15px var(--color-primary-glow)`;
  
  // Play translation animation across the pipeline
  animateNetworkFlow();

  try {
    const endpoint = scheme === 'paillier' ? '/api/send-paillier' : '/api/send-rsa';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meterId, value: val, isSecure })
    });
    
    const data = await res.json();
    
    if (data.success) {
      if (scheme === 'paillier') {
        // Add reading to visual buffer
        addPaillierToBuffer(meterId, val, data.details.ciphertext);
      } else {
        // Show RSA multi-step progress and verification results
        showRsaVerification(meterId, val, data.details);
      }
    } else {
      alert(`Error al procesar petición: ${data.error}`);
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
  } finally {
    btn.disabled = false;
    meterCard.style.boxShadow = '';
  }
}

// Add encrypted value to Paillier visual buffer
function addPaillierToBuffer(meterId, value, ciphertext) {
  // Check if meter reading is already in buffer, if so replace it
  const existingIdx = paillierBuffer.findIndex(b => b.meterId === meterId);
  const dataItem = { meterId, value, ciphertext };

  if (existingIdx !== -1) {
    paillierBuffer[existingIdx] = dataItem;
  } else {
    paillierBuffer.push(dataItem);
  }

  // Update ciphertext grid
  renderBufferGrid();
}

function renderBufferGrid() {
  ciphertextGrid.innerHTML = '';
  
  if (paillierBuffer.length === 0) {
    ciphertextGrid.innerHTML = `<div class="empty-buffer-text">Buzón vacío. Envía consumos cifrados desde los contadores.</div>`;
    bufferCount.textContent = `0 / 3`;
    btnAggregate.disabled = true;
    return;
  }

  paillierBuffer.forEach(item => {
    const cardName = item.meterId === 1 ? 'Hogar 1' : item.meterId === 2 ? 'Comercio 2' : 'Industria 3';
    const cipherBox = document.createElement('div');
    cipherBox.className = 'cipher-box';
    cipherBox.innerHTML = `
      <div class="lock-icon">🔒</div>
      <span>c${item.meterId} (${cardName})</span>
      <div class="cipher-snippet" title="${item.ciphertext}">${item.ciphertext.substring(0, 10)}...</div>
    `;
    ciphertextGrid.appendChild(cipherBox);
  });

  bufferCount.textContent = `${paillierBuffer.length} / 3`;
  
  // Enable aggregation button if we have at least 1 reading
  btnAggregate.disabled = paillierBuffer.length === 0;
}

// Aggregator Action: Homomorphic sum
async function triggerAggregation() {
  btnAggregate.disabled = true;
  btnAggregate.textContent = 'Agregando...';
  
  // Play beautiful merge animation inside aggregator grid
  ciphertextGrid.style.transition = 'all 0.5s ease';
  ciphertextGrid.style.opacity = 0.5;

  try {
    const res = await fetch('/api/aggregate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isSecure })
    });
    
    const data = await res.json();
    
    if (data.success) {
      // 1. Show merged ciphertext box
      ciphertextGrid.innerHTML = `
        <div class="cipher-box combined">
          <div class="lock-icon">🔒🔒🔒</div>
          <span>Consumo Homomórfico Acumulado (c_sum)</span>
          <div class="cipher-snippet" title="${data.details.ciphertextSum}">${data.details.ciphertextSum.substring(0, 45)}...</div>
        </div>
      `;
      ciphertextGrid.style.opacity = 1;

      // 2. Display mathematical formula in Aggregator
      paillierFormulaBox.classList.remove('hidden');
      paillierFormulaDetails.textContent = `c_sum = [${paillierBuffer.map(b => b.ciphertext.substring(0, 8) + '...').join(' * ')}] mod n²`;

      // 3. Update Utility Receiving box to show the "Combined Lock" has arrived!
      utilityReceiveBox.classList.add('has-data');
      paillierCombinedLock.textContent = '🔒';
      paillierCombinedLock.style.color = 'var(--color-accent)';
      paillierCombinedLock.style.filter = 'drop-shadow(0 0 15px var(--color-accent))';
      utilityReceiveTitle.textContent = 'Candado Acumulado Recibido';
      utilityReceiveDesc.textContent = '¡El Agregador combinó las 3 entradas en este único candado dorado cifrado de forma agregada!';

      // 4. Enable Decrypt button on Utility Column
      btnDecrypt.disabled = false;
      
      // Store the final decrypted sum data for the next step
      btnDecrypt.dataset.sumVal = data.details.decryptedSum;

    } else {
      alert(`Error de agregación: ${data.error}`);
      renderBufferGrid();
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
    renderBufferGrid();
  } finally {
    btnAggregate.textContent = 'Sumar Homomórficamente';
  }
}

// Utility Action: Decrypt Homomorphic Sum
function decryptSum() {
  btnDecrypt.disabled = true;
  
  // Laser decrypt animation
  paillierCombinedLock.style.transform = 'scale(1.2)';
  
  setTimeout(() => {
    paillierCombinedLock.textContent = '🔓';
    paillierCombinedLock.style.color = 'var(--color-success)';
    paillierCombinedLock.style.filter = 'drop-shadow(0 0 20px var(--color-success))';
    utilityReceiveTitle.textContent = 'Lectura Descifrada';
    utilityReceiveDesc.textContent = 'Clave privada aplicada con éxito sobre el candado acumulado.';

    // Reveal Ledger
    ledgerBox.classList.remove('hidden');
    ledgerConsumoVal.textContent = `${btnDecrypt.dataset.sumVal} kWh`;

    // Clear Agregador visuals to complete the demo loop
    paillierBuffer = [];
    bufferCount.textContent = '0 / 3';
    btnAggregate.disabled = true;
  }, 1000);
}

// Aggregator Action: Reset Buffer
async function resetBuffer() {
  try {
    const res = await fetch('/api/reset-buffer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isSecure })
    });
    
    const data = await res.json();
    if (data.success) {
      paillierBuffer = [];
      renderBufferGrid();
      
      // Reset Utility Receiving Box
      utilityReceiveBox.classList.remove('has-data');
      paillierCombinedLock.textContent = '🔒';
      paillierCombinedLock.style.color = '';
      paillierCombinedLock.style.filter = '';
      utilityReceiveTitle.textContent = 'Esperando Cifrado Agregado';
      utilityReceiveDesc.textContent = 'El agregador enviará un único candado matemático acumulado.';
      btnDecrypt.disabled = true;
      ledgerBox.classList.add('hidden');
      paillierFormulaBox.classList.add('hidden');
    }
  } catch (err) {
    alert('Error al resetear el buffer del agregador.');
  }
}

// RSA Blind Signature visual display logic
function showRsaVerification(meterId, originalMsg, details) {
  // Column 2: Aggregator / Pipeline visual flow progress
  rsaStepsBox.classList.remove('hidden');
  rsaStep1.className = 'rsa-step-item completed';
  rsaStep2.className = 'rsa-step-item completed';
  rsaStep3.className = 'rsa-step-item completed';
  rsaStep4.className = 'rsa-step-item completed';
  
  rsaVisualIcon.textContent = '🔏';
  rsaVisualIcon.style.color = 'var(--color-success)';
  rsaAggStatusTitle.textContent = 'Firma Ciega Realizada';
  rsaAggStatusDesc.textContent = `La central firmó el mensaje cegado m' de forma segura. El cliente A completó el descegado exitosamente.`;

  // Column 3: Utility / Signature central visual updates
  rsaReceiveBox.classList.add('has-data');
  rsaLockIllustration.textContent = '🔏';
  rsaLockIllustration.style.color = 'var(--color-utility)';
  rsaLockIllustration.style.filter = 'drop-shadow(0 0 15px var(--color-utility))';
  rsaReceiveTitle.textContent = 'Firma Emitida a Ciegas';
  rsaReceiveDesc.textContent = `Se aplicó la clave privada RSA sobre el número cegado m' sin conocer su contenido.`;

  // Column 3: Show detailed verification card
  rsaVerifyBox.classList.remove('hidden');
  rsaOriginalVal.textContent = originalMsg;
  rsaFinalSigVal.textContent = `${details.s.substring(0, 18)}...`;
  rsaFinalSigVal.title = details.s;
  rsaVerificationVal.textContent = details.verifiedMsg;

  if (details.verifiedMsg === originalMsg) {
    rsaVerificationBadge.textContent = 'VERIFICACIÓN: ÉXITO ✅';
    rsaVerificationBadge.className = 'verification-badge success';
  } else {
    rsaVerificationBadge.textContent = 'VERIFICACIÓN: FALLO ❌';
    rsaVerificationBadge.className = 'verification-badge';
  }
}
