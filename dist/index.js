"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const net_1 = require("net");
const process_manager_1 = require("./process-manager");
const config_1 = require("./config");
const axios_1 = __importDefault(require("axios"));
const os_1 = require("os");
const child_process_1 = require("child_process");
const fs_1 = require("fs");
dotenv_1.default.config();
const app = (0, express_1.default)();
// Fonction pour vérifier si un port est disponible
const checkPortAvailable = (port) => {
    return new Promise((resolve) => {
        const server = (0, net_1.createServer)();
        server.listen(port, () => {
            server.once('close', () => resolve(true));
            server.close();
        });
        server.on('error', () => {
            resolve(false);
        });
    });
};
// Fonction pour trouver un port disponible entre min et max
const findAvailablePort = async (min, max) => {
    for (let port = min; port <= max; port++) {
        const isAvailable = await checkPortAvailable(port);
        if (isAvailable) {
            return port;
        }
    }
    throw new Error(`Aucun port disponible entre ${min} et ${max}`);
};
// Fonction pour récupérer l'IP de la machine
const getLocalIP = () => {
    const interfaces = (0, os_1.networkInterfaces)();
    // Chercher d'abord une IP IPv4 non localhost
    for (const name of Object.keys(interfaces)) {
        const nets = interfaces[name];
        if (nets) {
            for (const net of nets) {
                // Ignorer les interfaces internes et non IPv4
                if (net.family === 'IPv4' && !net.internal) {
                    return net.address;
                }
            }
        }
    }
    // Si aucune IP externe trouvée, chercher localhost
    for (const name of Object.keys(interfaces)) {
        const nets = interfaces[name];
        if (nets) {
            for (const net of nets) {
                if (net.family === 'IPv4') {
                    return net.address;
                }
            }
        }
    }
    return '127.0.0.1';
};
// Fonction pour vérifier l'autorisation auprès du cluster
const checkAuthorization = async (appUrl) => {
    const config = await (0, config_1.readConfig)();
    if (!config.url || !config.token) {
        console.error('ERREUR: Configuration manquante. Vous devez être connecté au cluster.');
        console.error('Utilisez: firewall connect <url> <token>');
        return false;
    }
    const ip = getLocalIP();
    const checkUrl = config.url.endsWith('/')
        ? `${config.url}api/connect/check`
        : `${config.url}/api/connect/check`;
    try {
        console.log(`Vérification de l'autorisation auprès du cluster...`);
        console.log(`URL: ${checkUrl}`);
        console.log(`IP: ${ip}`);
        console.log(`App URL: ${appUrl}`);
        const response = await axios_1.default.post(checkUrl, {
            ip: ip,
            token: config.token,
            url: appUrl
        }, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 10000 // 10 secondes de timeout
        });
        if (response.data && response.data.authorized === true && response.data.complete === true) {
            console.log('Autorisation confirmée par le cluster');
            if (response.data.server) {
                console.log(`Serveur: ${response.data.server.hostname || response.data.server.address}`);
            }
            return true;
        }
        else {
            if (response.data) {
                if (response.data.authorized !== true) {
                    console.error('ERREUR: Non autorisé par le cluster');
                }
                else if (response.data.complete !== true) {
                    console.error('ERREUR: Configuration incomplète. Le serveur n\'est pas complètement configuré.');
                }
                console.error('Réponse:', JSON.stringify(response.data, null, 2));
            }
            else {
                console.error('ERREUR: Réponse invalide du cluster');
            }
            return false;
        }
    }
    catch (error) {
        console.error('ERREUR: Impossible de vérifier l\'autorisation auprès du cluster');
        if (error.response) {
            console.error(`Code: ${error.response.status} - ${error.response.statusText}`);
            if (error.response.data) {
                console.error('Détails:', JSON.stringify(error.response.data, null, 2));
            }
        }
        else if (error.request) {
            console.error('Aucune réponse du serveur. Vérifiez que le cluster est accessible.');
        }
        else {
            console.error('Erreur:', error.message);
        }
        return false;
    }
};
// Middleware pour parser le JSON
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
// Route de test
app.get('/', (req, res) => {
    res.json({
        message: 'Serveur Express en TypeScript fonctionne!',
        status: 'OK'
    });
});
// Route d'API exemple
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});
// Fonction pour obtenir l'utilisation CPU en temps réel
const getCPUUsage = async () => {
    const cpusInfo = (0, os_1.cpus)();
    if (cpusInfo.length === 0) {
        return { usage: 0, model: 'Unknown' };
    }
    try {
        // Fonction pour lire les stats CPU depuis /proc/stat
        const readCPUStats = async () => {
            const stat = await fs_1.promises.readFile('/proc/stat', 'utf-8');
            const cpuLine = stat.split('\n')[0]; // Première ligne (cpu total)
            const parts = cpuLine.trim().split(/\s+/);
            // user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
            const user = parseInt(parts[1]) || 0;
            const nice = parseInt(parts[2]) || 0;
            const system = parseInt(parts[3]) || 0;
            const idle = parseInt(parts[4]) || 0;
            const iowait = parseInt(parts[5]) || 0;
            const irq = parseInt(parts[6]) || 0;
            const softirq = parseInt(parts[7]) || 0;
            const steal = parseInt(parts[8]) || 0;
            const total = user + nice + system + idle + iowait + irq + softirq + steal;
            return { total, idle };
        };
        // Première mesure
        const stats1 = await readCPUStats();
        // Attendre 1 seconde
        await new Promise(resolve => setTimeout(resolve, 1000));
        // Deuxième mesure
        const stats2 = await readCPUStats();
        // Calculer la différence
        const totalDiff = stats2.total - stats1.total;
        const idleDiff = stats2.idle - stats1.idle;
        // Calculer le pourcentage d'utilisation
        const usage = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
        return {
            usage: Math.max(0, Math.min(100, Math.round(usage * 100) / 100)),
            model: cpusInfo[0].model || 'Unknown'
        };
    }
    catch (error) {
        // Fallback si /proc/stat n'est pas accessible (Windows par exemple)
        return {
            usage: 0,
            model: cpusInfo[0].model || 'Unknown'
        };
    }
};
// Fonction pour obtenir l'utilisation RAM
const getRAMUsage = () => {
    const total = (0, os_1.totalmem)();
    const free = (0, os_1.freemem)();
    const used = total - free;
    const totalGB = total / (1024 * 1024 * 1024);
    const usedGB = used / (1024 * 1024 * 1024);
    const usagePercent = (used / total) * 100;
    return {
        usagePercent: Math.round(usagePercent * 100) / 100,
        usedGB: Math.round(usedGB * 100) / 100,
        totalGB: Math.round(totalGB * 100) / 100
    };
};
// Fonction pour obtenir l'utilisation du disque
const getDiskUsage = async () => {
    try {
        if ((0, os_1.platform)() === 'win32') {
            // Windows - utiliser wmic
            const output = (0, child_process_1.execSync)('wmic logicaldisk get size,freespace,caption', { encoding: 'utf-8' });
            const lines = output.split('\n').filter(line => line.trim() && !line.includes('Caption'));
            let totalSize = 0;
            let totalFree = 0;
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 3) {
                    const free = parseInt(parts[0]) || 0;
                    const size = parseInt(parts[1]) || 0;
                    totalFree += free;
                    totalSize += size;
                }
            }
            const total = totalSize;
            const used = totalSize - totalFree;
            const totalGB = total / (1024 * 1024 * 1024);
            const usedGB = used / (1024 * 1024 * 1024);
            const usagePercent = (used / total) * 100;
            return {
                usagePercent: Math.round(usagePercent * 100) / 100,
                usedGB: Math.round(usedGB * 100) / 100,
                totalGB: Math.round(totalGB * 100) / 100
            };
        }
        else {
            // Linux/Unix - utiliser df
            const output = (0, child_process_1.execSync)('df -BG /', { encoding: 'utf-8' });
            const lines = output.split('\n');
            if (lines.length >= 2) {
                const parts = lines[1].trim().split(/\s+/);
                if (parts.length >= 4) {
                    const totalGB = parseFloat(parts[1].replace('G', ''));
                    const usedGB = parseFloat(parts[2].replace('G', ''));
                    const usagePercent = parseFloat(parts[4].replace('%', ''));
                    return {
                        usagePercent: Math.round(usagePercent * 100) / 100,
                        usedGB: Math.round(usedGB * 100) / 100,
                        totalGB: Math.round(totalGB * 100) / 100
                    };
                }
            }
        }
    }
    catch (error) {
        // En cas d'erreur, retourner des valeurs par défaut
    }
    return {
        usagePercent: 0,
        usedGB: 0,
        totalGB: 0
    };
};
// Fonction pour obtenir l'utilisation de la bande passante en Mbps et pps (Linux uniquement)
const getNetworkUsage = async () => {
    if ((0, os_1.platform)() === 'win32') {
        return {
            in: { mbps: 0, pps: 0 },
            out: { mbps: 0, pps: 0 }
        };
    }
    try {
        // Fonction helper pour lire les stats réseau (exclure loopback)
        const readNetworkStats = async () => {
            const netDev = await fs_1.promises.readFile('/proc/net/dev', 'utf-8');
            const lines = netDev.split('\n').slice(2); // Ignorer les deux premières lignes
            let totalRx = 0;
            let totalTx = 0;
            let totalRxPackets = 0;
            let totalTxPackets = 0;
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    const interfaceName = parts[0].replace(':', '');
                    // Exclure l'interface loopback (lo) et les interfaces virtuelles communes
                    if (interfaceName === 'lo' ||
                        interfaceName.startsWith('docker') ||
                        interfaceName.startsWith('veth') ||
                        interfaceName.startsWith('br-') ||
                        interfaceName.startsWith('virbr')) {
                        continue;
                    }
                    const rx = parseInt(parts[1]) || 0;
                    const tx = parseInt(parts[9]) || 0;
                    const rxPackets = parseInt(parts[2]) || 0;
                    const txPackets = parseInt(parts[10]) || 0;
                    totalRx += rx;
                    totalTx += tx;
                    totalRxPackets += rxPackets;
                    totalTxPackets += txPackets;
                }
            }
            return {
                rx: totalRx,
                tx: totalTx,
                rxPackets: totalRxPackets,
                txPackets: totalTxPackets
            };
        };
        // Première mesure
        const stats1 = await readNetworkStats();
        // Attendre 1 seconde
        await new Promise(resolve => setTimeout(resolve, 1000));
        // Deuxième mesure
        const stats2 = await readNetworkStats();
        // Calculer la différence (bytes par seconde)
        const rxDiff = stats2.rx - stats1.rx;
        const txDiff = stats2.tx - stats1.tx;
        // Calculer la différence de paquets (paquets par seconde)
        const rxPacketsDiff = stats2.rxPackets - stats1.rxPackets;
        const txPacketsDiff = stats2.txPackets - stats1.txPackets;
        // Convertir en Mbps (mégabits par seconde)
        // 1 byte = 8 bits, 1 Mbps = 1 000 000 bits par seconde
        const inMbps = (rxDiff * 8) / 1000000;
        const outMbps = (txDiff * 8) / 1000000;
        return {
            in: {
                mbps: Math.max(0, Math.round(inMbps * 100) / 100),
                pps: Math.max(0, rxPacketsDiff)
            },
            out: {
                mbps: Math.max(0, Math.round(outMbps * 100) / 100),
                pps: Math.max(0, txPacketsDiff)
            }
        };
    }
    catch (error) {
        return {
            in: { mbps: 0, pps: 0 },
            out: { mbps: 0, pps: 0 }
        };
    }
};
// Route pour obtenir le statut de l'application
app.get('/api/status', async (req, res) => {
    try {
        const ip = getLocalIP();
        const status = await (0, process_manager_1.getStatus)();
        const config = await (0, config_1.readConfig)();
        // Récupérer les informations système
        const cpu = await getCPUUsage();
        const ram = getRAMUsage();
        const disk = await getDiskUsage();
        const network = await getNetworkUsage();
        res.json({
            ip: ip,
            up: status.running,
            connectedTo: config.url || null,
            cpu: {
                usage: cpu.usage,
                model: cpu.model
            },
            ram: {
                usagePercent: ram.usagePercent,
                usedGB: ram.usedGB,
                totalGB: ram.totalGB
            },
            disk: {
                usagePercent: disk.usagePercent,
                usedGB: disk.usedGB,
                totalGB: disk.totalGB
            },
            network: {
                in: {
                    mbps: network.in.mbps,
                    pps: network.in.pps
                },
                out: {
                    mbps: network.out.mbps,
                    pps: network.out.pps
                }
            }
        });
    }
    catch (error) {
        res.status(500).json({
            error: 'Erreur lors de la récupération du statut',
            message: error instanceof Error ? error.message : String(error)
        });
    }
});
// Démarrage du serveur avec détection automatique du port
const startServer = async () => {
    // Vérifier que la configuration existe
    const hasConfig = await (0, config_1.isConfigComplete)();
    if (!hasConfig) {
        console.error('ERREUR: Configuration manquante. Vous devez être connecté au cluster.');
        console.error('Utilisez: firewall connect <url> <token>');
        process.exit(1);
    }
    const minPort = parseInt(process.env.MIN_PORT || '3000');
    const maxPort = parseInt(process.env.MAX_PORT || '3100');
    try {
        const PORT = await findAvailablePort(minPort, maxPort);
        const ip = getLocalIP();
        const appUrl = `http://${ip}:${PORT}`;
        // Vérifier l'autorisation auprès du cluster avec l'URL de l'app
        const isAuthorized = await checkAuthorization(appUrl);
        if (!isAuthorized) {
            console.error('ERREUR: Non autorisé par le cluster. Démarrage annulé.');
            process.exit(1);
        }
        // Sauvegarder le PID et le statut
        await (0, process_manager_1.writePid)(process.pid);
        await (0, process_manager_1.writeStatus)({
            running: true,
            pid: process.pid,
            port: PORT,
            startedAt: new Date().toISOString()
        });
        app.listen(PORT, () => {
            console.log(`Serveur démarré sur le port ${PORT}`);
            console.log(`URL: http://localhost:${PORT}`);
            console.log(`URL publique: ${appUrl}`);
            console.log(`PID: ${process.pid}`);
        });
    }
    catch (error) {
        console.error('Erreur lors du démarrage du serveur:', error);
        process.exit(1);
    }
};
// Gestion de l'arrêt propre
process.on('SIGTERM', async () => {
    console.log('Réception du signal SIGTERM, arrêt en cours...');
    await (0, process_manager_1.writeStatus)({ running: false });
    process.exit(0);
});
process.on('SIGINT', async () => {
    console.log('Réception du signal SIGINT, arrêt en cours...');
    await (0, process_manager_1.writeStatus)({ running: false });
    process.exit(0);
});
startServer();
//# sourceMappingURL=index.js.map