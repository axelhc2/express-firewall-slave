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
const iptables_1 = require("./iptables");
const axios_1 = __importDefault(require("axios"));
const os_1 = require("os");
const child_process_1 = require("child_process");
const util_1 = require("util");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
const FIREWALL_DEBUG = process.env.FIREWALL_DEBUG === '1' || process.env.FIREWALL_DEBUG === 'true';
const logDebug = (...args) => {
    if (FIREWALL_DEBUG)
        console.log(...args);
};
const fs_1 = require("fs");
dotenv_1.default.config();
const app = (0, express_1.default)();
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
const findAvailablePort = async (min, max) => {
    for (let port = min; port <= max; port++) {
        const isAvailable = await checkPortAvailable(port);
        if (isAvailable) {
            return port;
        }
    }
    throw new Error(`Aucun port disponible entre ${min} et ${max}`);
};
const getLocalIP = () => {
    const interfaces = (0, os_1.networkInterfaces)();
    for (const name of Object.keys(interfaces)) {
        const nets = interfaces[name];
        if (nets) {
            for (const net of nets) {
                if (net.family === 'IPv4' && !net.internal) {
                    return net.address;
                }
            }
        }
    }
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
const getPublicIP = async () => {
    try {
        const response = await axios_1.default.get('http://185.189.158.161:3000/api/ip', {
            timeout: 5000
        });
        if (response.data && response.data.ipv4) {
            return response.data.ipv4;
        }
    }
    catch (error) {
        console.warn('Impossible de récupérer l\'IP publique via l\'API, utilisation de l\'IP locale');
    }
    return getLocalIP();
};
const checkAuthorization = async (appUrl) => {
    const config = await (0, config_1.readConfig)();
    if (!config.url || !config.token) {
        console.error('ERREUR: Configuration manquante. Vous devez être connecté au cluster.');
        console.error('Utilisez: firewall connect <url> <token>');
        return false;
    }
    const ip = await getPublicIP();
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
            timeout: 10000
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
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
const authenticateToken = async (req, res, next) => {
    try {
        const config = await (0, config_1.readConfig)();
        if (!config.token) {
            return res.status(401).json({
                error: 'Token non configuré',
                message: 'Le serveur n\'a pas de token configuré'
            });
        }
        const authHeader = req.headers.authorization;
        let token;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        }
        else {
            token = req.headers['x-token'];
        }
        if (!token) {
            return res.status(401).json({
                error: 'Token manquant',
                message: 'Veuillez fournir un token d\'authentification dans le header Authorization ou X-Token'
            });
        }
        if (token !== config.token) {
            return res.status(403).json({
                error: 'Token invalide',
                message: 'Le token fourni n\'est pas valide'
            });
        }
        next();
    }
    catch (error) {
        return res.status(500).json({
            error: 'Erreur d\'authentification',
            message: error instanceof Error ? error.message : String(error)
        });
    }
};
app.get('/', (req, res) => {
    res.json({
        message: 'Serveur Express en TypeScript fonctionne!',
        status: 'OK'
    });
});
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});
const getCPUUsage = async () => {
    const cpusInfo = (0, os_1.cpus)();
    if (cpusInfo.length === 0) {
        return { usage: 0, model: 'Unknown' };
    }
    try {
        const readCPUStats = async () => {
            const stat = await fs_1.promises.readFile('/proc/stat', 'utf-8');
            const cpuLine = stat.split('\n')[0];
            const parts = cpuLine.trim().split(/\s+/);
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
        const stats1 = await readCPUStats();
        await new Promise(resolve => setTimeout(resolve, 1000));
        const stats2 = await readCPUStats();
        const totalDiff = stats2.total - stats1.total;
        const idleDiff = stats2.idle - stats1.idle;
        const usage = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
        return {
            usage: Math.max(0, Math.min(100, Math.round(usage * 100) / 100)),
            model: cpusInfo[0].model || 'Unknown'
        };
    }
    catch (error) {
        return {
            usage: 0,
            model: cpusInfo[0].model || 'Unknown'
        };
    }
};
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
const getDiskUsage = async () => {
    try {
        if ((0, os_1.platform)() === 'win32') {
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
    }
    return {
        usagePercent: 0,
        usedGB: 0,
        totalGB: 0
    };
};
const getNetworkUsage = async () => {
    if ((0, os_1.platform)() === 'win32') {
        return {
            in: { mbps: 0, pps: 0 },
            out: { mbps: 0, pps: 0 }
        };
    }
    try {
        const readNetworkStats = async () => {
            const netDev = await fs_1.promises.readFile('/proc/net/dev', 'utf-8');
            const lines = netDev.split('\n').slice(2);
            let totalRx = 0;
            let totalTx = 0;
            let totalRxPackets = 0;
            let totalTxPackets = 0;
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    const interfaceName = parts[0].replace(':', '');
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
        const stats1 = await readNetworkStats();
        await new Promise(resolve => setTimeout(resolve, 1000));
        const stats2 = await readNetworkStats();
        const rxDiff = stats2.rx - stats1.rx;
        const txDiff = stats2.tx - stats1.tx;
        const rxPacketsDiff = stats2.rxPackets - stats1.rxPackets;
        const txPacketsDiff = stats2.txPackets - stats1.txPackets;
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
app.get('/api/status', async (req, res) => {
    try {
        const ip = await getPublicIP();
        const status = await (0, process_manager_1.getStatus)();
        const config = await (0, config_1.readConfig)();
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
app.get('/api/iptables/view', authenticateToken, async (req, res) => {
    try {
        const lines = req.query.lines ? parseInt(req.query.lines, 10) : undefined;
        const ip = req.query.ip;
        const port = req.query.port;
        const action = req.query.action;
        const top = req.query.top ? parseInt(req.query.top, 10) : undefined;
        const actionFilter = action && ['DROP', 'REJECT', 'ACCEPT', 'LOG'].includes(action.toUpperCase())
            ? action.toUpperCase()
            : undefined;
        if (ip) {
            const logs = await (0, iptables_1.getLogsByIP)(ip, actionFilter);
            return res.json({
                success: true,
                ip: ip,
                action: actionFilter || 'ALL',
                count: logs.length,
                logs: logs
            });
        }
        if (port) {
            const logs = await (0, iptables_1.getLogsByPort)(port, actionFilter);
            return res.json({
                success: true,
                port: port,
                action: actionFilter || 'ALL',
                count: logs.length,
                logs: logs
            });
        }
        if (action && !top) {
            const logs = await (0, iptables_1.getLogsByAction)(action);
            return res.json({
                success: true,
                action: action.toUpperCase(),
                count: logs.length,
                logs: logs
            });
        }
        if (top) {
            const topIPs = await (0, iptables_1.getTopBlockedIPs)(top, actionFilter);
            return res.json({
                success: true,
                top: top,
                action: actionFilter || 'ALL',
                ips: topIPs
            });
        }
        const stats = await (0, iptables_1.readIptablesLogs)(lines, actionFilter);
        res.json({
            success: true,
            totalEntries: stats.totalEntries,
            byAction: stats.byAction,
            topIPs: Object.entries(stats.byIP)
                .map(([ip, data]) => ({
                ip,
                count: data.count,
                actions: data.actions,
                ports: data.ports
            }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 20),
            byPort: Object.entries(stats.byPort)
                .map(([port, data]) => ({
                port,
                count: data.count,
                topIPs: Object.entries(data.ips)
                    .map(([ip, count]) => ({ ip, count }))
                    .sort((a, b) => b.count - a.count)
                    .slice(0, 10)
            }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 20),
            recentEntries: stats.entries.slice(-100),
            logFile: stats.logFile,
            error: stats.error,
            info: stats.totalEntries === 0 && !stats.error
                ? 'Aucun log iptables trouvé. Assurez-vous d\'avoir des règles LOG dans iptables avant les règles DROP/REJECT.'
                : undefined
        });
    }
    catch (error) {
        res.status(500).json({
            success: false,
            error: 'Erreur lors de la lecture des logs iptables',
            message: error instanceof Error ? error.message : String(error)
        });
    }
});
// Fonction pour appliquer les règles sauvegardées au démarrage (si nécessaire)
// Note: Avec iptables, les règles sont appliquées directement par le cluster
// Cette fonction est conservée pour compatibilité mais ne fait rien par défaut
const applySavedRules = async () => {
    // Avec iptables, les règles sont gérées directement par le cluster via l'API
    // Pas besoin de charger un fichier au démarrage comme avec nftables
    logDebug('[firewall] démarrage sans règles pré-chargées (iptables géré par le cluster)');
};
// Fonction pour valider qu'une commande commence par iptables (sécurité)
const validateIptablesCommand = (command) => {
    const trimmed = command.trim();
    if (!trimmed)
        return false;
    // Extraire la commande principale (avant || ou ;)
    let mainCommand = trimmed;
    if (trimmed.includes('||')) {
        // Pour "cmd || iptables ...", prendre la partie après ||
        const parts = trimmed.split('||');
        mainCommand = parts[parts.length - 1]?.trim() || trimmed;
    }
    else if (trimmed.includes(';')) {
        // Pour "cmd; iptables ...", prendre la partie après ;
        const parts = trimmed.split(';');
        mainCommand = parts[parts.length - 1]?.trim() || trimmed;
    }
    // Vérifier que la commande principale commence par "iptables"
    const normalized = mainCommand.toLowerCase();
    return normalized.startsWith('iptables ') || normalized.startsWith('iptables\t');
};
// Fonction pour exécuter une commande iptables avec timeout
const executeIptablesCommand = async (command) => {
    try {
        logDebug(`[firewall] exécution: ${command}`);
        const { stdout, stderr } = await execAsync(command, {
            timeout: 10000, // 10 secondes de timeout
            maxBuffer: 1024 * 1024 // 1MB max
        });
        return {
            success: true,
            stdout: stdout || undefined,
            stderr: stderr || undefined
        };
    }
    catch (error) {
        // Les commandes avec || true ou 2>/dev/null peuvent échouer sans bloquer
        // C'est normal, on considère ça comme un succès si le code de sortie est acceptable
        const hasErrorHandling = command.includes('|| true') || command.includes('2>/dev/null');
        if (hasErrorHandling && error.code === 1) {
            // Commande avec gestion d'erreur qui a échoué mais c'est attendu
            return {
                success: true,
                stdout: error.stdout || undefined,
                stderr: error.stderr || undefined
            };
        }
        return {
            success: false,
            stdout: error.stdout || undefined,
            stderr: error.stderr || undefined,
            error: error.message
        };
    }
};
app.post('/api/firewall/rules/apply', authenticateToken, async (req, res) => {
    try {
        const { commands, flush } = req.body;
        if (!commands) {
            return res.status(400).json({
                error: 'Commande manquante',
                message: 'Veuillez fournir des commandes dans le body de la requête (field "commands")'
            });
        }
        const commandsList = Array.isArray(commands) ? commands : [commands];
        // Validation: toutes les commandes doivent être des strings
        const invalidCommands = commandsList.filter(cmd => typeof cmd !== 'string');
        if (invalidCommands.length > 0) {
            return res.status(400).json({
                error: 'Format invalide',
                message: 'Toutes les commandes doivent être des chaînes de caractères'
            });
        }
        // Validation de sécurité: vérifier que chaque commande commence par iptables
        const invalidSecurityCommands = commandsList.filter(cmd => !validateIptablesCommand(cmd));
        if (invalidSecurityCommands.length > 0) {
            return res.status(400).json({
                error: 'Sécurité: commande invalide',
                message: 'Toutes les commandes doivent commencer par "iptables"',
                invalidCommands: invalidSecurityCommands
            });
        }
        const results = [];
        let executed = 0;
        // Si flush est true, on flush d'abord les règles iptables
        if (flush === true) {
            logDebug('[firewall] flush des règles iptables demandé');
            const flushCommands = [
                'iptables -F',
                'iptables -X'
            ];
            for (const flushCmd of flushCommands) {
                const result = await executeIptablesCommand(flushCmd);
                results.push({
                    command: flushCmd,
                    success: result.success,
                    error: result.error
                });
                if (result.success)
                    executed++;
                logDebug(`[firewall] ${result.success ? '✓' : '✗'} ${flushCmd}`);
            }
        }
        // Exécuter les commandes une par une dans l'ordre
        for (const command of commandsList) {
            const result = await executeIptablesCommand(command);
            results.push({
                command: command,
                success: result.success,
                error: result.error
            });
            if (result.success)
                executed++;
            logDebug(`[firewall] ${result.success ? '✓' : '✗'} ${command}`);
        }
        const allSuccess = results.every(r => r.success);
        const successCount = results.filter(r => r.success).length;
        res.status(allSuccess ? 200 : 207).json({
            success: allSuccess,
            message: `${successCount} commande(s) exécutée(s) avec succès`,
            results: results,
            executed: executed
        });
    }
    catch (error) {
        res.status(500).json({
            error: 'Erreur lors de l\'application des règles',
            message: error instanceof Error ? error.message : String(error)
        });
    }
});
const startServer = async () => {
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
        const ip = await getPublicIP();
        const appUrl = `http://${ip}:${PORT}`;
        const isAuthorized = await checkAuthorization(appUrl);
        if (!isAuthorized) {
            console.error('ERREUR: Non autorisé par le cluster. Démarrage annulé.');
            process.exit(1);
        }
        await applySavedRules();
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