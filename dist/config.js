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
exports.isConfigComplete = exports.clearConfig = exports.writeConfig = exports.readConfig = void 0;
const fs_1 = require("fs");
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const CONFIG_FILE = path.join(os.homedir(), '.firewall', 'config.json');
// Créer le répertoire de configuration s'il n'existe pas
const ensureConfigDir = async () => {
    const configDir = path.dirname(CONFIG_FILE);
    try {
        await fs_1.promises.mkdir(configDir, { recursive: true });
    }
    catch (error) {
        // Le répertoire existe déjà, c'est OK
    }
};
// Lire la configuration
const readConfig = async () => {
    try {
        await ensureConfigDir();
        const data = await fs_1.promises.readFile(CONFIG_FILE, 'utf-8');
        return JSON.parse(data);
    }
    catch {
        return {};
    }
};
exports.readConfig = readConfig;
// Écrire la configuration
const writeConfig = async (config) => {
    await ensureConfigDir();
    // Lire la config existante et la fusionner avec la nouvelle
    const existingConfig = await (0, exports.readConfig)();
    const newConfig = {
        ...existingConfig,
        ...config,
        connectedAt: config.url && config.token ? new Date().toISOString() : existingConfig.connectedAt
    };
    await fs_1.promises.writeFile(CONFIG_FILE, JSON.stringify(newConfig, null, 2), 'utf-8');
};
exports.writeConfig = writeConfig;
// Supprimer la configuration
const clearConfig = async () => {
    try {
        await fs_1.promises.unlink(CONFIG_FILE);
    }
    catch {
        // Le fichier n'existe pas, c'est OK
    }
};
exports.clearConfig = clearConfig;
// Vérifier si la configuration est complète
const isConfigComplete = async () => {
    const config = await (0, exports.readConfig)();
    return !!(config.url && config.token);
};
exports.isConfigComplete = isConfigComplete;
//# sourceMappingURL=config.js.map