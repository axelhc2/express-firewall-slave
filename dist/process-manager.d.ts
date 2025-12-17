export interface FirewallStatus {
    running: boolean;
    pid?: number;
    port?: number;
    startedAt?: string;
}
export declare const isProcessRunning: (pid: number) => Promise<boolean>;
export declare const readPid: () => Promise<number | null>;
export declare const writePid: (pid: number) => Promise<void>;
export declare const removePid: () => Promise<void>;
export declare const readStatus: () => Promise<FirewallStatus | null>;
export declare const writeStatus: (status: FirewallStatus) => Promise<void>;
export declare const getStatus: () => Promise<FirewallStatus>;
export declare const startServer: () => Promise<number>;
export declare const stopServer: () => Promise<void>;
export declare const rebootServer: () => Promise<number>;
//# sourceMappingURL=process-manager.d.ts.map