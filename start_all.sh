#!/bin/bash

# ==============================================================================
# SCIOTS: Orquestador y Arrancador Unificado
# ==============================================================================

# Guardar la ruta raíz del proyecto
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$ROOT_DIR"

echo "======================================================================"
echo "          INICIANDO ARQUITECTURA DISTRIBUIDA SCIOTS"
echo "======================================================================"

# 1. Limpieza de procesos colgados previos
echo "🧹 Limpiando procesos antiguos en puertos SCIOTS..."
killall coap-http-reverseproxy 2>/dev/null
# Matar procesos de Node que corran en nuestros puertos para evitar "Port in use"
fuser -k 3000/tcp 2>/dev/null
fuser -k 4000/tcp 2>/dev/null
fuser -k 5000/tcp 2>/dev/null
fuser -k 6000/tcp 2>/dev/null
sleep 1

# Array para guardar los PIDs de los subprocesos y poder pararlos juntos
PIDS=()

# Función que se ejecuta al pulsar Ctrl+C para apagar todo ordenadamente
function shutdown_all() {
    echo -e "\n\n🛑 DETENIENDO TODOS LOS SERVICIOS DE FORMA SEGURA..."
    
    # Matar proxies CoAP
    killall coap-http-reverseproxy 2>/dev/null
    
    # Matar todos los servicios Node iniciados por este script
    for pid in "${PIDS[@]}"; do
        if kill -0 $pid 2>/dev/null; then
            kill $pid 2>/dev/null
        fi
    done
    
    echo "✔ Todos los servicios y proxies se han detenido correctamente."
    echo "======================================================================"
    exit 0
}

# Capturar señal de interrupción (Ctrl+C)
trap shutdown_all SIGINT SIGTERM

# 2. Levantar Microservicios Node.js en segundo plano
echo "🚀 Lanzando Microservicio 1: Compañía Eléctrica (serverE:3000)..."
node serverE/index.js > /tmp/sciots_serverE.log 2>&1 &
PIDS+=($!)

echo "🚀 Lanzando Microservicio 2: Agregador Homomórfico (aggregator:4000)..."
node aggregator/index.js > /tmp/sciots_aggregator.log 2>&1 &
PIDS+=($!)

echo "🚀 Lanzando Microservicio 3: Contadores Inteligentes (meters:6000)..."
node meters/index.js > /tmp/sciots_meters.log 2>&1 &
PIDS+=($!)

sleep 1

# 3. Lanzar los proxies de CoAP en segundo plano
echo "🛰️ Iniciando pasarelas y proxies CoAP (UDP)..."
chmod +x ./run_proxies.sh
./run_proxies.sh > /tmp/sciots_proxies_start.log 2>&1 &
PIDS+=($!)

sleep 1

# 4. Lanzar el Dashboard principal
echo "💻 Iniciando Servidor del Dashboard Visual (dashboard:5000)..."
node dashboard/server.js &
PIDS+=($!)

echo "======================================================================"
echo "🎉 ¡TODOS LOS COMPONENTES ESTÁN EN MARCHA!"
echo "   ➔ Dashboard Web:   http://localhost:5000"
echo "   ➔ Logs de red activos en la consola..."
echo "======================================================================"
echo "👉 Mantén esta terminal abierta para ver logs."
echo "👉 Pulsa [ Ctrl + C ] en esta ventana para APAGAR todos los servicios a la vez."
echo "======================================================================"

# Mostrar logs de la consola en vivo o mantener en espera
# Hacemos un tail en vivo de los logs clave
tail -f /tmp/sciots_meters.log &
TAIL_PID=$!

# Asegurar que el tail también muera al pulsar Ctrl+C
function clean_tail() {
    kill $TAIL_PID 2>/dev/null
    shutdown_all
}
trap clean_tail SIGINT SIGTERM

# Mantener el script activo esperando Ctrl+C
wait
