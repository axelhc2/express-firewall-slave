export interface IptablesLogEntry {
    timestamp: string;
    action: string;
    src: string;
    dst: string;
    dpt?: string;
    spt?: string;
    proto: string;
    raw: string;
}
export interface IptablesStats {
    totalEntries: number;
    byAction: {
        [action: string]: number;
    };
    byIP: {
        [ip: string]: {
            count: number;
            actions: {
                [action: string]: number;
            };
            ports: {
                [port: string]: number;
            };
        };
    };
    byPort: {
        [port: string]: {
            count: number;
            ips: {
                [ip: string]: number;
            };
        };
    };
    entries: IptablesLogEntry[];
    error?: string;
    logFile?: string;
}
export declare const readIptablesLogs: (lines?: number, actionFilter?: string) => Promise<IptablesStats>;
export declare const getTopBlockedIPs: (limit?: number, actionFilter?: string) => Promise<Array<{
    ip: string;
    count: number;
    actions: {
        [action: string]: number;
    };
}>>;
export declare const getLogsByIP: (ip: string, actionFilter?: string) => Promise<IptablesLogEntry[]>;
export declare const getLogsByPort: (port: string, actionFilter?: string) => Promise<IptablesLogEntry[]>;
export declare const getLogsByAction: (action: string) => Promise<IptablesLogEntry[]>;
//# sourceMappingURL=iptables.d.ts.map