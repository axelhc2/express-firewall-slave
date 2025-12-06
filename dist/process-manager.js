"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.rebootServer = exports.stopServer = exports.startServer = exports.getStatus = exports.writeStatus = exports.readStatus = exports.removePid = exports.writePid = exports.readPid = exports.isProcessRunning = void 0;
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const PID_FILE = path.join(os.tmpdir(), 'backfirewall.pid');
const STATUS_FILE = path.join(os.tmpdir(), 'backfirewall.status');
// Vérifier si un processus est en cours d'exécution
const isProcessRunning = async (pid) => {
    try {
        process.kill(pid, 0);
        return true;
    }
    catch {
        return false;
    }
};
exports.isProcessRunning = isProcessRunning;
// Lire le PID depuis le fichier
const readPid = async () => {
    try {
        const data = await fs_1.promises.readFile(PID_FILE, 'utf-8');
        const pid = parseInt(data.trim(), 10);
        if (isNaN(pid))
            return null;
        return pid;
    }
    catch {
        return null;
    }
};
exports.readPid = readPid;
// Écrire le PID dans le fichier
const writePid = async (pid) => {
    await fs_1.promises.writeFile(PID_FILE, pid.toString(), 'utf-8');
};
exports.writePid = writePid;
// Supprimer le fichier PID
const removePid = async () => {
    try {
        await fs_1.promises.unlink(PID_FILE);
    }
    catch {
        // Fichier n'existe pas, c'est OK
    }
};
exports.removePid = removePid;
// Lire le statut depuis le fichier
const readStatus = async () => {
    try {
        const data = await fs_1.promises.readFile(STATUS_FILE, 'utf-8');
        return JSON.parse(data);
    }
    catch {
        return null;
    }
};
exports.readStatus = readStatus;
// Écrire le statut dans le fichier
const writeStatus = async (status) => {
    await fs_1.promises.writeFile(STATUS_FILE, JSON.stringify(status, null, 2), 'utf-8');
};
exports.writeStatus = writeStatus;
// Obtenir le statut actuel du firewall
const getStatus = async () => {
    const savedStatus = await (0, exports.readStatus)();
    const pid = await (0, exports.readPid)();
    if (!pid || !savedStatus) {
        return { running: false };
    }
    const isRunning = await (0, exports.isProcessRunning)(pid);
    if (!isRunning) {
        // Processus mort, nettoyer
        await (0, exports.removePid)();
        await (0, exports.writeStatus)({ running: false });
        return { running: false };
    }
    return {
        ...savedStatus,
        running: true,
        pid
    };
};
exports.getStatus = getStatus;
// Démarrer le serveur
const startServer = async () => {
    return new Promise((resolve, reject) => {
        // Vérifier si déjà en cours d'exécution
        (0, exports.getStatus)().then(async (status) => {
            if (status.running) {
                reject(new Error('Le firewall est déjà en cours d\'exécution'));
                return;
            }
            // Démarrer le serveur en arrière-plan
            const serverProcess = (0, child_process_1.spawn)('node', [path.join(__dirname, 'index.js')], {
                detached: true,
                stdio: 'ignore',
                cwd: path.dirname(__dirname)
            });
            serverProcess.unref();
            // Vérifier que le PID est défini
            if (!serverProcess.pid) {
                reject(new Error('Impossible d\'obtenir le PID du processus'));
                return;
            }
            const pid = serverProcess.pid;
            // Attendre un peu pour vérifier que le processus démarre
            setTimeout(async () => {
                try {
                    process.kill(pid, 0);
                    await (0, exports.writePid)(pid);
                    // Lire le port depuis les variables d'environnement ou utiliser une valeur par défaut
                    const minPort = parseInt(process.env.MIN_PORT || '3000', 10);
                    const status = {
                        running: true,
                        pid: pid,
                        port: minPort, // On pourrait améliorer cela en lisant depuis un fichier de log
                        startedAt: new Date().toISOString()
                    };
                    await (0, exports.writeStatus)(status);
                    resolve(pid);
                }
                catch (error) {
                    reject(new Error(`Erreur lors du démarrage: ${error}`));
                }
            }, 1000);
        });
    });
};
exports.startServer = startServer;
// Arrêter le serveur
const stopServer = async () => {
    const status = await (0, exports.getStatus)();
    if (!status.running || !status.pid) {
        throw new Error('Le firewall n\'est pas en cours d\'exécution');
    }
    try {
        process.kill(status.pid, 'SIGTERM');
        // Attendre que le processus se termine
        let attempts = 0;
        while (attempts < 10) {
            const isRunning = await (0, exports.isProcessRunning)(status.pid);
            if (!isRunning) {
                break;
            }
            await new Promise(resolve => setTimeout(resolve, 500));
            attempts++;
        }
        // Si toujours en cours, forcer l'arrêt
        if (await (0, exports.isProcessRunning)(status.pid)) {
            process.kill(status.pid, 'SIGKILL');
        }
        await (0, exports.removePid)();
        await (0, exports.writeStatus)({ running: false });
    }
    catch (error) {
        throw new Error(`Erreur lors de l'arrêt: ${error}`);
    }
};
exports.stopServer = stopServer;
// Redémarrer le serveur
const rebootServer = async () => {
    const status = await (0, exports.getStatus)();
    if (status.running) {
        await (0, exports.stopServer)();
        // Attendre un peu avant de redémarrer
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return await (0, exports.startServer)();
};
exports.rebootServer = rebootServer;
//# sourceMappingURL=process-manager.js.map