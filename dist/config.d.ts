export interface FirewallConfig {
    url?: string;
    token?: string;
    connectedAt?: string;
}
export declare const readConfig: () => Promise<FirewallConfig>;
export declare const writeConfig: (config: Partial<FirewallConfig>) => Promise<void>;
export declare const clearConfig: () => Promise<void>;
export declare const isConfigComplete: () => Promise<boolean>;
//# sourceMappingURL=config.d.ts.map