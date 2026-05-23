// ==========================================================================
// SCIOTS Premium Dashboard Logic (Vanilla ES6)
// ==========================================================================

const activeScheme = 'paillier'; // Fixed: the system always uses Paillier + RSA signature
let isSecure = false;
let paillierBuffer = [];
let sentMeters = new Set(); // tracks which meter IDs have already sent this cycle
let statusInterval = null;
let logsInterval = null;

// DOM Elements
const secureModeToggle = document.getElementById('secureModeToggle');


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
const aggPubKeyVal = document.getElementById('aggPubKeyVal');
const btnSignSend = document.getElementById('btnSignSend');

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  fetchInitialKeys();
  startPolling();
  
  // Initialize connection cables and listeners
  drawCables();
  window.addEventListener('resize', drawCables);
  // Re-run after fonts and columns are rendered to ensure exact coordinates
  setTimeout(drawCables, 500);
  
  // Custom terminal initial lines
  appendLocalLog('SISTEMA', 'system', 'Consola del Dashboard lista. Conectando con los microservicios...');
});

// Event Listeners Setup
function setupEventListeners() {
  // Protocol Toggle (CoAP plain / CoAPs DTLS)
  secureModeToggle.addEventListener('change', (e) => {
    isSecure = e.target.checked;
    updateProtocolPorts();
    fetchInitialKeys();
    appendLocalLog('SISTEMA', 'system', `Modo de seguridad cambiado a: ${isSecure ? 'CoAPs (DTLS + PSK)' : 'CoAP (Plano)'}`);
  });
}

function updateProtocolPorts() {
  // Paillier flow: meters → proxy (UDP 5685/5686) → aggregator (TCP 4000)
  coapPortLabel.textContent = isSecure ? 'Puerto UDP 5686 (DTLS)' : 'Puerto UDP 5685';
  httpPortLabel.textContent = 'Puerto TCP 4000';
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
  if (aggPubKeyVal) aggPubKeyVal.textContent = 'Cargando...';

  // 1. Fetch Central Public Key via clean read-only endpoint (no aggregator side effects)
  try {
    const keyEndpoint = activeScheme === 'paillier' ? '/api/paillier-key' : '/api/rsa-key';
    const res = await fetch(`${keyEndpoint}?isSecure=${isSecure}`);
    const data = await res.json();
    if (data.n) {
      pubKeyVal.textContent = `n = ${data.n.substring(0, 20)}...`;
      pubKeyVal.title = `n = ${data.n}`;
    } else {
      pubKeyVal.textContent = 'Error al conectar';
    }
  } catch (err) {
    pubKeyVal.textContent = 'Fuera de línea';
  }

  // 2. Fetch Aggregator Public Key (read-only, no side effects)
  if (activeScheme === 'paillier' && aggPubKeyVal) {
    try {
      const res = await fetch('/api/aggregator/key');
      const data = await res.json();
      if (data.n) {
        aggPubKeyVal.textContent = `n = ${data.n.substring(0, 20)}...`;
        aggPubKeyVal.title = `n = ${data.n}`;
      } else {
        aggPubKeyVal.textContent = 'Error al conectar';
      }
    } catch (err) {
      aggPubKeyVal.textContent = 'Fuera de línea';
    }
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
  
  // Play physical packet traveling along the entire sequence (Meter -> Proxy -> Aggregator)
  const animStart = Date.now();
  const ANIM_DURATION = 2800; // matches animateCablePacket total duration in ms
  animateCablePacket(meterId);

  try {
    const endpoint = scheme === 'paillier' ? '/api/send-paillier' : '/api/send-rsa';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meterId, value: val, isSecure })
    });
    
    const data = await res.json();
    
    if (data.success) {
      const elapsed = Date.now() - animStart;
      const remaining = Math.max(0, ANIM_DURATION - elapsed);

      if (scheme === 'paillier') {
        // Wait until the animated packet visually lands in the aggregator, then show cipher box
        setTimeout(() => {
          addPaillierToBuffer(meterId, val, data.details.ciphertext);
          // Button stays LOCKED for the rest of the cycle — unlocked only on cycle reset
          meterCard.style.boxShadow = '';
        }, remaining);
      } else {
        // RSA: sync visual steps to animation arrival too
        setTimeout(() => {
          showRsaVerification(meterId, val, data.details);
          // Mark meter as sent so it can't be re-sent this cycle
          sentMeters.add(meterId);
          meterCard.style.boxShadow = '';
        }, remaining);
      }
    } else {
      // On error unlock immediately — nothing was committed
      alert(`Error al procesar petición: ${data.error}`);
      btn.disabled = false;
      meterCard.style.boxShadow = '';
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
    btn.disabled = false;
    meterCard.style.boxShadow = '';
  }
}

// Add encrypted value to Paillier visual buffer
function addPaillierToBuffer(meterId, value, ciphertext) {
  // Mark meter as sent — locked for the rest of the cycle
  sentMeters.add(meterId);

  // Update or insert the reading in the buffer
  const existingIdx = paillierBuffer.findIndex(b => b.meterId === meterId);
  const dataItem = { meterId, value, ciphertext };

  if (existingIdx !== -1) {
    paillierBuffer[existingIdx] = dataItem;
  } else {
    paillierBuffer.push(dataItem);
  }

  // Mark the button as permanently sent (cycle-locked)
  const meterCard = document.getElementById(`meter${meterId}`);
  if (meterCard) {
    const btn = meterCard.querySelector('.btn-send');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '✔ Enviado';
      btn.style.background = 'linear-gradient(135deg, #166534, #15803d)';
      btn.style.cursor = 'not-allowed';
    }
    meterCard.style.boxShadow = '';
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

// Aggregator Action: Homomorphic sum (Only packages/multiplies)
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
          <span>Consumo Cifrado Agregado (c_sum)</span>
          <div class="cipher-snippet" title="${data.details.ciphertextSum}">${data.details.ciphertextSum.substring(0, 45)}...</div>
        </div>
      `;
      ciphertextGrid.style.opacity = 1;

      // 2. Display mathematical formula in Aggregator
      paillierFormulaBox.classList.remove('hidden');
      paillierFormulaDetails.textContent = `c_sum = [${paillierBuffer.map(b => b.ciphertext.substring(0, 8) + '...').join(' * ')}] mod n²`;

      // 3. Update Utility Receiving box state
      utilityReceiveBox.classList.add('has-data');
      paillierCombinedLock.textContent = '🔒';
      paillierCombinedLock.style.color = 'var(--color-accent)';
      paillierCombinedLock.style.filter = 'drop-shadow(0 0 15px var(--color-accent))';
      utilityReceiveTitle.textContent = 'Suma Cifrada Empaquetada';
      utilityReceiveDesc.textContent = '¡Candado acumulado listo! Ahora debe ser firmado digitalmente por el agregador para autenticarse antes de enviarlo para descifrar.';

      // 4. Hide "Sumar Homomórficamente" and show "Firmar y Enviar"
      btnAggregate.classList.add('hidden');
      btnSignSend.classList.remove('hidden');
      btnSignSend.disabled = false;

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

// Aggregator Action: Sign the aggregated sum and send to Central for verification
async function triggerSignAndSend() {
  btnSignSend.disabled = true;
  btnSignSend.textContent = 'Firmando y Enviando...';

  // Play animation representing the signed transmission flowing across proxy network
  animateNetworkFlow();

  try {
    const res = await fetch('/api/sign-and-send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ isSecure })
    });

    const data = await res.json();

    if (data.success) {
      // 1. Launch the signed-packet cable animation: Aggregator → Utility
      animateSignedPacket();

      // 2. Update visual padlock on Central (Utility) to show signed transmission is pending verification
      paillierCombinedLock.style.transform = 'scale(1.2)';
      
      setTimeout(() => {
        paillierCombinedLock.textContent = '🔏';
        paillierCombinedLock.style.color = '#fbbf24'; // Warning color (gold)
        paillierCombinedLock.style.filter = 'drop-shadow(0 0 15px #fbbf24)';
        utilityReceiveTitle.textContent = 'Firma y Cifrado Recibidos';
        utilityReceiveDesc.textContent = '¡Cifrado firmado recibido del Agregador! Primero se debe verificar la firma digital del Agregador para autenticar la procedencia de los datos.';

        // Enable "Verificar Firma del Agregador"
        const btnVerifySig = document.getElementById('btnVerifySig');
        btnVerifySig.disabled = false;
        btnVerifySig.classList.remove('hidden');
        btnVerifySig.textContent = '1. Verificar Firma del Agregador';

        // Hide Decrypt button (until verified)
        btnDecrypt.disabled = true;
        btnDecrypt.classList.add('hidden');

        // 2. Clear Agregador buffer and reset UI buttons
        paillierBuffer = [];
        bufferCount.textContent = '0 / 3';
        btnAggregate.classList.remove('hidden');
        btnAggregate.disabled = true;
        btnSignSend.classList.add('hidden');

        // 3. Unlock all meter send buttons for the next cycle
        resetMeterButtons();
      }, 1000);

    } else {
      alert(`Error en firma/envío: ${data.error}`);
      btnSignSend.disabled = false;
      btnSignSend.textContent = '✍️ Firmar y Enviar';
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
    btnSignSend.disabled = false;
    btnSignSend.textContent = '✍️ Firmar y Enviar';
  }
}

// Utility Action: Verify the Aggregator's RSA Signature
async function verifySignature() {
  const btnVerifySig = document.getElementById('btnVerifySig');
  btnVerifySig.disabled = true;
  btnVerifySig.textContent = 'Verificando firma...';

  try {
    const res = await fetch('/api/verify-signature', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await res.json();

    if (data.success) {
      paillierCombinedLock.style.transform = 'scale(1.2)';
      setTimeout(() => {
        paillierCombinedLock.textContent = '✅';
        paillierCombinedLock.style.color = 'var(--color-success)';
        paillierCombinedLock.style.filter = 'drop-shadow(0 0 15px var(--color-success))';
        utilityReceiveTitle.textContent = 'Firma RSA Verificada';
        utilityReceiveDesc.textContent = '¡Éxito! La firma digital del Agregador es VÁLIDA y AUTÉNTICA. El origen del cifrado está garantizado. Ahora puedes descifrar la suma consolidada.';
        
        btnVerifySig.classList.add('hidden');
        btnDecrypt.classList.remove('hidden');
        btnDecrypt.disabled = false;
        btnDecrypt.textContent = '2. Descifrar Consumo con Clave Privada';
      }, 1000);
    } else {
      alert(`Error al verificar firma: ${data.error}`);
      btnVerifySig.disabled = false;
      btnVerifySig.textContent = '1. Verificar Firma del Agregador';
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
    btnVerifySig.disabled = false;
    btnVerifySig.textContent = '1. Verificar Firma del Agregador';
  }
}

// Utility Action: Decrypt Homomorphic Sum using Paillier Private Key
async function decryptSum() {
  btnDecrypt.disabled = true;
  btnDecrypt.textContent = 'Descifrando...';

  try {
    const res = await fetch('/api/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await res.json();

    if (data.success) {
      paillierCombinedLock.style.transform = 'scale(1.2)';
      setTimeout(() => {
        paillierCombinedLock.textContent = '🔓';
        paillierCombinedLock.style.color = 'var(--color-success)';
        paillierCombinedLock.style.filter = 'drop-shadow(0 0 20px var(--color-success))';
        utilityReceiveTitle.textContent = 'Suma Descifrada';
        utilityReceiveDesc.textContent = '¡Éxito! Clave privada Paillier aplicada correctamente. El total ha sido descifrado y registrado en el libro.';

        // Reveal Ledger with decrypted sum
        ledgerBox.classList.remove('hidden');
        ledgerConsumoVal.textContent = `${data.decrypted} kWh`;

        btnDecrypt.disabled = true;
        btnDecrypt.textContent = 'Descifrado Completado';
      }, 1000);
    } else {
      alert(`Error al descifrar: ${data.error}`);
      btnDecrypt.disabled = false;
      btnDecrypt.textContent = '2. Descifrar Consumo con Clave Privada';
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
    btnDecrypt.disabled = false;
    btnDecrypt.textContent = '2. Descifrar Consumo con Clave Privada';
  }
}

// Reset all meter send buttons at the start of a new cycle
function resetMeterButtons() {
  sentMeters.clear();
  [1, 2, 3].forEach(id => {
    const meterCard = document.getElementById(`meter${id}`);
    if (meterCard) {
      const btn = meterCard.querySelector('.btn-send');
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Enviar Cifrado';
        btn.style.background = '';
        btn.style.cursor = '';
      }
      meterCard.style.boxShadow = '';
    }
  });
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

      // Unlock all meter send buttons for the next cycle
      resetMeterButtons();
      
      // Reset Utility Receiving Box
      utilityReceiveBox.classList.remove('has-data');
      paillierCombinedLock.textContent = '🔒';
      paillierCombinedLock.style.color = '';
      paillierCombinedLock.style.filter = '';
      utilityReceiveTitle.textContent = 'Esperando Cifrado Agregado';
      utilityReceiveDesc.textContent = 'El agregador enviará un único candado matemático acumulado.';
      
      const btnVerifySig = document.getElementById('btnVerifySig');
      btnVerifySig.disabled = true;
      btnVerifySig.classList.remove('hidden');
      btnVerifySig.textContent = '1. Verificar Firma del Agregador';
      
      btnDecrypt.disabled = true;
      btnDecrypt.classList.add('hidden');
      btnDecrypt.textContent = '2. Descifrar Consumo con Clave Privada';
      
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

// Draw connection cables: Meters -> Proxy (CoAP Side) and Proxy (HTTP Side) -> Aggregator
function drawCables() {
  const container = document.querySelector('.grid-container');
  const svg = document.getElementById('cablesSvg');
  if (!container || !svg) return;

  const containerRect = container.getBoundingClientRect();

  const coapSide = document.getElementById('coapSide');
  const httpSide = document.getElementById('httpSide');
  const aggregatorCard = document.getElementById('aggregatorCard');

  if (!coapSide || !httpSide || !aggregatorCard) return;

  const coapRect = coapSide.getBoundingClientRect();
  const httpRect = httpSide.getBoundingClientRect();
  const aggRect = aggregatorCard.getBoundingClientRect();

  // --- 1. Draw curves: Meters to Proxy CoAP Side ---
  const targetX = coapRect.left - containerRect.left;
  const targetY = coapRect.top - containerRect.top + (coapRect.height / 2);

  for (let i = 1; i <= 3; i++) {
    const meterCard = document.getElementById(`meter${i}`);
    if (!meterCard) continue;

    const meterRect = meterCard.getBoundingClientRect();

    const startX = meterRect.right - containerRect.left;
    const startY = meterRect.top - containerRect.top + (meterRect.height / 2);

    const cp1x = startX + (targetX - startX) * 0.45;
    const cp1y = startY;
    const cp2x = startX + (targetX - startX) * 0.55;
    const cp2y = targetY;

    const d = `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${targetX} ${targetY}`;

    const cable = document.getElementById(`cable${i}`);
    const cableActive = document.getElementById(`cable${i}Active`);
    const motion = document.getElementById(`motion${i}`);

    if (cable) cable.setAttribute('d', d);
    if (cableActive) cableActive.setAttribute('d', d);
    if (motion) motion.setAttribute('path', d);
  }

  // --- 2. Draw curves: Proxy HTTP Side to Aggregator Card ---
  for (let i = 1; i <= 3; i++) {
    // Start distributed vertically along the right edge of the HTTP side of the proxy
    const startX = httpRect.right - containerRect.left;
    const startY = httpRect.top - containerRect.top + (httpRect.height * (0.25 * i));

    // End distributed vertically along the left edge of the Aggregator card
    const endX = aggRect.left - containerRect.left;
    const endY = aggRect.top - containerRect.top + (aggRect.height * (0.25 * i));

    // Smooth horizontal S-curve
    const cp1x = startX + (endX - startX) * 0.45;
    const cp1y = startY;
    const cp2x = startX + (endX - startX) * 0.55;
    const cp2y = endY;

    const d = `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${endX} ${endY}`;

    const cable = document.getElementById(`cable${i}_to_agg`);
    const cableActive = document.getElementById(`cable${i}_to_aggActive`);
    const motion = document.getElementById(`motion${i}_to_agg`);

    if (cable) cable.setAttribute('d', d);
    if (cableActive) cableActive.setAttribute('d', d);
    if (motion) motion.setAttribute('path', d);
  }

  // --- 3. Draw curve: Aggregator Card to Utility Card ---
  const utilityCard = document.getElementById('utilityCard');
  if (utilityCard) {
    const utilRect = utilityCard.getBoundingClientRect();

    const startX = aggRect.right - containerRect.left;
    const startY = aggRect.top - containerRect.top + aggRect.height / 2;

    const endX = utilRect.left - containerRect.left;
    const endY = utilRect.top - containerRect.top + utilRect.height / 2;

    const cp1x = startX + (endX - startX) * 0.45;
    const cp1y = startY;
    const cp2x = startX + (endX - startX) * 0.55;
    const cp2y = endY;

    const d = `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${endX} ${endY}`;

    const cableUtil = document.getElementById('cable_agg_to_util');
    const cableUtilActive = document.getElementById('cable_agg_to_utilActive');
    const motionUtil = document.getElementById('motion_agg_to_util');

    if (cableUtil) cableUtil.setAttribute('d', d);
    if (cableUtilActive) cableUtilActive.setAttribute('d', d);
    if (motionUtil) motionUtil.setAttribute('path', d);
  }
}

// Animate a signed packet traveling from Aggregator to Utility (amber colour = RSA signature)
function animateSignedPacket() {
  const packet = document.getElementById('packet_agg_to_util');
  const motion = document.getElementById('motion_agg_to_util');
  const cableActive = document.getElementById('cable_agg_to_utilActive');

  if (!packet || !motion || !cableActive) return;

  // Light up the cable
  cableActive.style.opacity = '1';

  // Launch the amber packet
  packet.style.display = 'block';
  motion.beginElement();

  // Hide after 1.2s travel + 0.3s fade
  setTimeout(() => {
    packet.style.display = 'none';
    cableActive.style.opacity = '0';
  }, 1600);
}

// Animate a packet traveling from the meter card to the Proxy, translating, and then to the Aggregator
function animateCablePacket(meterId) {
  const packet = document.getElementById(`packet${meterId}`);
  const motion = document.getElementById(`motion${meterId}`);
  const cableActive = document.getElementById(`cable${meterId}Active`);

  const packetToAgg = document.getElementById(`packet${meterId}_to_agg`);
  const motionToAgg = document.getElementById(`motion${meterId}_to_agg`);
  const cableToAggActive = document.getElementById(`cable${meterId}_to_aggActive`);

  if (!packet || !motion || !cableActive || !packetToAgg || !motionToAgg || !cableToAggActive) return;

  const themeColor = activeScheme === 'paillier' ? 'var(--color-primary)' : 'var(--color-accent)';
  const successColor = 'var(--color-success)';

  // --- Phase 1: Meter to Proxy (CoAP / UDP) ---
  const circle = packet.querySelector('circle');
  if (circle) {
    circle.setAttribute('fill', themeColor);
    circle.style.filter = `drop-shadow(0 0 8px ${themeColor})`;
  }
  cableActive.style.stroke = themeColor;
  cableActive.style.opacity = '1';

  packet.style.display = 'block';
  motion.beginElement();

  // --- Phase 2: Translation inside Proxy (CoAP -> HTTP) ---
  setTimeout(() => {
    packet.style.display = 'none';
    cableActive.style.opacity = '0';

    // Play translation animation inside the gateway connector
    animateNetworkFlow();
  }, 1000); // 1.0s dur

  // --- Phase 3: Proxy to Aggregator (HTTP / TCP) ---
  setTimeout(() => {
    cableToAggActive.style.stroke = successColor;
    cableToAggActive.style.opacity = '1';

    const circleToAgg = packetToAgg.querySelector('circle');
    if (circleToAgg) {
      circleToAgg.setAttribute('fill', successColor);
      circleToAgg.style.filter = `drop-shadow(0 0 8px ${successColor})`;
    }

    packetToAgg.style.display = 'block';
    motionToAgg.beginElement();
  }, 1800); // 1.0s motion + 0.8s translation

  // --- Phase 4: Arrival at Aggregator ---
  setTimeout(() => {
    packetToAgg.style.display = 'none';
    cableToAggActive.style.opacity = '0';
  }, 2800); // 1.8s + 1.0s motion
}
