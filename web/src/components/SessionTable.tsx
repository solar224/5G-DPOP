import { useState, useEffect, useMemo } from 'react';
import { SessionInfo, fetchSessions } from '../services/api';

// 格式化 bytes
function formatBytes(bytes: number): string {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// 格式化 RFC3339 時間戳
function formatTimestamp(ts: string | undefined): string {
    if (!ts) return 'N/A';
    try {
        const date = new Date(ts);
        if (isNaN(date.getTime())) return ts;
        return date.toLocaleString('zh-TW', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch {
        return ts;
    }
}

// Session 詳細資訊 Modal
interface SessionDetailModalProps {
    session: SessionInfo;
    onClose: () => void;
    theme: 'dark' | 'light';
}

function SessionDetailModal({ session, onClose, theme }: SessionDetailModalProps) {
    const firstTeid = session.teids?.[0] || 'N/A';

    // Theme variables
    const modalBg = theme === 'dark' ? 'bg-gray-800' : 'bg-white';
    const sectionBg = theme === 'dark' ? 'bg-gray-700/50' : 'bg-gray-100';
    const textPrimary = theme === 'dark' ? 'text-white' : 'text-gray-900';
    const textSecondary = theme === 'dark' ? 'text-gray-400' : 'text-gray-600';
    const borderColor = theme === 'dark' ? 'border-gray-600' : 'border-gray-300';
    const footerBg = theme === 'dark' ? 'bg-gray-700/50' : 'bg-gray-100';

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className={`${modalBg} rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto`}>
                {/* Header */}
                <div className="bg-gradient-to-r from-cyan-600 to-blue-600 px-6 py-4 rounded-t-xl flex justify-between items-center sticky top-0">
                    <div>
                        <h2 className="text-xl font-bold text-white">PDU Session 詳細資訊</h2>
                        <p className="text-cyan-100 text-sm">SEID: {session.seid}</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-white hover:bg-white/20 rounded-full p-2 transition-colors"
                    >
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="p-6 space-y-6">
                    {/* 基本識別資訊 */}
                    <section>
                        <h3 className="text-lg font-semibold text-cyan-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                            </svg>
                            用戶識別
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <InfoCard
                                label="SUPI (用戶永久識別)"
                                value={session.supi || '未提供'}
                                icon="🆔"
                                theme={theme}
                            />
                            <InfoCard
                                label="UE IP 地址"
                                value={session.ue_ip || 'N/A'}
                                icon="🌐"
                                theme={theme}
                            />
                            <InfoCard
                                label="SEID (Session Endpoint ID)"
                                value={session.seid}
                                icon="🔗"
                                theme={theme}
                            />
                            <InfoCard
                                label="TEID (Tunnel Endpoint ID)"
                                value={firstTeid}
                                icon="🚇"
                                theme={theme}
                            />
                        </div>
                    </section>

                    {/* 網路與 QoS 資訊 */}
                    <section>
                        <h3 className="text-lg font-semibold text-green-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
                            </svg>
                            網路與 QoS 資訊
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <InfoCard
                                label="DNN (Data Network Name)"
                                value={session.dnn || '未解析'}
                                icon="📡"
                                theme={theme}
                            />
                            <InfoCard
                                label="QFI (QoS Flow ID)"
                                value={session.qfi?.toString() || 'N/A'}
                                icon="⚡"
                                theme={theme}
                            />
                        </div>
                    </section>

                    {/* 網路節點資訊 */}
                    <section>
                        <h3 className="text-lg font-semibold text-purple-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                            </svg>
                            GTP-U 隧道資訊
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className={`${sectionBg} rounded-lg p-4 border border-purple-500/30`}>
                                <h4 className="text-purple-300 font-medium mb-2">📤 UPF 端點</h4>
                                <div className="space-y-2">
                                    <div className="flex justify-between">
                                        <span className={textSecondary}>IP 地址:</span>
                                        <span className={`${textPrimary} font-mono`}>{session.upf_ip || '未知'}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className={textSecondary}>TEID UL (gNB→UPF):</span>
                                        <span className={`${textPrimary} font-mono text-sm text-green-400`}>
                                            {session.teid_ul || session.teids?.[0] || 'N/A'}
                                        </span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className={textSecondary}>TEID DL (UPF→gNB):</span>
                                        <span className={`${textPrimary} font-mono text-sm text-blue-400`}>
                                            {session.teid_dl || session.teids?.[1] || 'N/A'}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div className={`${sectionBg} rounded-lg p-4 border border-blue-500/30`}>
                                <h4 className="text-blue-300 font-medium mb-2">📥 gNB 端點</h4>
                                <div className="space-y-2">
                                    <div className="flex justify-between">
                                        <span className={textSecondary}>IP 地址:</span>
                                        <span className={`${textPrimary} font-mono`}>{session.gnb_ip || '未知'}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* 頻寬限制 */}
                    {(session.mbr_ul_kbps || session.mbr_dl_kbps) && (
                        <section>
                            <h3 className="text-lg font-semibold text-orange-400 mb-3 flex items-center gap-2">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                </svg>
                                頻寬限制 (MBR)
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {session.mbr_ul_kbps && (
                                    <InfoCard
                                        label="MBR 上行"
                                        value={`${(session.mbr_ul_kbps / 1000).toFixed(0)} Mbps`}
                                        icon="⬆️"
                                        theme={theme}
                                    />
                                )}
                                {session.mbr_dl_kbps && (
                                    <InfoCard
                                        label="MBR 下行"
                                        value={`${(session.mbr_dl_kbps / 1000).toFixed(0)} Mbps`}
                                        icon="⬇️"
                                        theme={theme}
                                    />
                                )}
                            </div>
                        </section>
                    )}

                    {/* 流量統計 */}
                    <section>
                        <h3 className="text-lg font-semibold text-yellow-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                            流量統計
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <StatCard
                                label="上行封包數"
                                value={(session.packets_ul || 0).toLocaleString()}
                                icon="📤"
                                color="blue"
                                theme={theme}
                            />
                            <StatCard
                                label="下行封包數"
                                value={(session.packets_dl || 0).toLocaleString()}
                                icon="📥"
                                color="green"
                                theme={theme}
                            />
                            <StatCard
                                label="上行流量"
                                value={formatBytes(session.bytes_ul || 0)}
                                icon="⬆️"
                                color="blue"
                                theme={theme}
                            />
                            <StatCard
                                label="下行流量"
                                value={formatBytes(session.bytes_dl || 0)}
                                icon="⬇️"
                                color="green"
                                theme={theme}
                            />
                        </div>
                        <div className={`mt-4 ${sectionBg} rounded-lg p-4`}>
                            <div className="flex justify-between items-center">
                                <span className={textSecondary}>總流量</span>
                                <span className={`text-xl font-bold ${textPrimary}`}>
                                    {formatBytes((session.bytes_ul || 0) + (session.bytes_dl || 0))}
                                </span>
                            </div>
                            {((session.bytes_ul || 0) + (session.bytes_dl || 0)) > 0 && (
                                <>
                                    <div className={`mt-2 w-full ${theme === 'dark' ? 'bg-gray-600' : 'bg-gray-300'} rounded-full h-2`}>
                                        <div
                                            className="bg-gradient-to-r from-blue-500 to-green-500 h-2 rounded-full"
                                            style={{
                                                width: `${((session.bytes_ul || 0) / ((session.bytes_ul || 0) + (session.bytes_dl || 0))) * 100}%`
                                            }}
                                        />
                                    </div>
                                    <div className={`flex justify-between text-xs ${textSecondary} mt-1`}>
                                        <span>上行: {(((session.bytes_ul || 0) / ((session.bytes_ul || 0) + (session.bytes_dl || 0))) * 100).toFixed(1)}%</span>
                                        <span>下行: {(((session.bytes_dl || 0) / ((session.bytes_ul || 0) + (session.bytes_dl || 0))) * 100).toFixed(1)}%</span>
                                    </div>
                                </>
                            )}
                        </div>
                    </section>

                    {/* 時間與狀態資訊 */}
                    <section>
                        <h3 className="text-lg font-semibold text-red-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            時間與狀態
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <InfoCard
                                label="建立時間"
                                value={formatTimestamp(session.created_at)}
                                icon="🕐"
                                theme={theme}
                            />
                            <InfoCard
                                label="Session 持續時間"
                                value={session.duration || 'N/A'}
                                icon="⏱️"
                                theme={theme}
                            />
                            <InfoCard
                                label="最後活動時間"
                                value={formatTimestamp(session.last_active)}
                                icon="🔄"
                                theme={theme}
                            />
                        </div>
                        <div className={`mt-4 ${sectionBg} rounded-lg p-4 border border-green-500/30`}>
                            <div className="flex items-center gap-3">
                                <div className={`w-3 h-3 rounded-full ${session.status === 'Active' ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
                                <span className={`text-lg font-medium ${textPrimary}`}>
                                    {session.status === 'Active' ? '🟢 活躍中' : session.status || '未知'}
                                </span>
                            </div>
                        </div>
                    </section>

                    {/* SEID ↔ TEID 關係圖 */}
                    <section>
                        <h3 className="text-lg font-semibold text-pink-400 mb-3 flex items-center gap-2">
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                            SEID ↔ TEID 映射關係
                        </h3>
                        <div className={`${theme === 'dark' ? 'bg-gray-900/50' : 'bg-gray-50'} rounded-lg p-4 border border-pink-500/30`}>
                            <div className="flex flex-col md:flex-row items-center justify-center gap-4">
                                <div className="bg-cyan-600/30 rounded-lg px-6 py-4 text-center border border-cyan-500">
                                    <div className="text-cyan-300 text-sm mb-1">PFCP Session</div>
                                    <div className={`${textPrimary} font-bold text-xl`}>SEID: {session.seid}</div>
                                </div>
                                <div className="flex flex-col items-center">
                                    <svg className="w-8 h-8 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
                                    </svg>
                                    <span className={`text-xs ${textSecondary}`}>對應</span>
                                </div>
                                <div className="bg-purple-600/30 rounded-lg px-6 py-4 text-center border border-purple-500">
                                    <div className="text-purple-300 text-sm mb-1">GTP-U Tunnel</div>
                                    <div className={`${textPrimary} font-bold text-lg`}>
                                        <span className="text-green-400">UL:</span> {session.teid_ul || session.teids?.[0] || 'N/A'}
                                    </div>
                                    <div className={`${textPrimary} font-bold text-lg`}>
                                        <span className="text-blue-400">DL:</span> {session.teid_dl || session.teids?.[1] || 'N/A'}
                                    </div>
                                </div>
                            </div>
                            <div className={`mt-4 text-center text-sm ${textSecondary}`}>
                                此 PDU Session 透過 PFCP 協定建立，並在用戶平面使用 GTP-U 隧道傳輸資料
                            </div>
                        </div>
                    </section>
                </div>

                {/* Footer */}
                <div className={`${footerBg} px-6 py-4 rounded-b-xl border-t ${borderColor}`}>
                    <button
                        onClick={onClose}
                        className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2 px-4 rounded-lg transition-colors"
                    >
                        關閉
                    </button>
                </div>
            </div>
        </div>
    );
}

// 資訊卡片元件
interface InfoCardProps {
    label: string;
    value: string;
    icon?: string;
    theme?: 'dark' | 'light';
}

function InfoCard({ label, value, icon, theme = 'dark' }: InfoCardProps) {
    const cardBg = theme === 'dark' ? 'bg-gray-700/50' : 'bg-gray-100';
    const borderColor = theme === 'dark' ? 'border-gray-600' : 'border-gray-300';
    const labelColor = theme === 'dark' ? 'text-gray-400' : 'text-gray-600';
    const valueColor = theme === 'dark' ? 'text-white' : 'text-gray-900';

    return (
        <div className={`${cardBg} rounded-lg p-3 border ${borderColor}`}>
            <div className={`${labelColor} text-xs mb-1 flex items-center gap-1`}>
                {icon && <span>{icon}</span>}
                {label}
            </div>
            <div className={`${valueColor} font-medium break-all`}>{value}</div>
        </div>
    );
}

// 統計卡片元件
interface StatCardProps {
    label: string;
    value: string;
    icon?: string;
    color?: 'blue' | 'green' | 'yellow' | 'red';
    theme?: 'dark' | 'light';
}

function StatCard({ label, value, icon, color = 'blue', theme = 'dark' }: StatCardProps) {
    const colorClasses = {
        blue: 'from-blue-500/20 to-blue-600/20 border-blue-500/30',
        green: 'from-green-500/20 to-green-600/20 border-green-500/30',
        yellow: 'from-yellow-500/20 to-yellow-600/20 border-yellow-500/30',
        red: 'from-red-500/20 to-red-600/20 border-red-500/30',
    };
    const labelColor = theme === 'dark' ? 'text-gray-400' : 'text-gray-600';
    const valueColor = theme === 'dark' ? 'text-white' : 'text-gray-900';

    return (
        <div className={`bg-gradient-to-br ${colorClasses[color]} rounded-lg p-3 border`}>
            <div className={`${labelColor} text-xs mb-1 flex items-center gap-1`}>
                {icon && <span>{icon}</span>}
                {label}
            </div>
            <div className={`${valueColor} font-bold text-lg`}>{value}</div>
        </div>
    );
}

// 主元件
interface SessionTableProps {
    theme?: 'dark' | 'light'
}

export default function SessionTable({ theme = 'dark' }: SessionTableProps) {
    const [sessions, setSessions] = useState<SessionInfo[]>([]);
    const [selectedSession, setSelectedSession] = useState<SessionInfo | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [sortField, setSortField] = useState<'seid' | 'ue_ip' | 'packets' | 'created_at'>('created_at');
    const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
    const [searchTerm, setSearchTerm] = useState('');

    // 載入 Sessions
    useEffect(() => {
        const loadSessions = async () => {
            setIsLoading(true);
            try {
                const result = await fetchSessions();
                setSessions(result.sessions || []);
                setError(null);
            } catch (err) {
                setError('無法載入 PDU Sessions');
                console.error(err);
            } finally {
                setIsLoading(false);
            }
        };

        loadSessions();
        const interval = setInterval(loadSessions, 5000);
        return () => clearInterval(interval);
    }, []);

    // 過濾和排序
    const filteredAndSortedSessions = useMemo(() => {
        let result = [...sessions];

        // 搜尋過濾
        if (searchTerm) {
            const term = searchTerm.toLowerCase();
            result = result.filter(s =>
                s.seid?.toLowerCase().includes(term) ||
                s.ue_ip?.toLowerCase().includes(term) ||
                s.supi?.toLowerCase().includes(term) ||
                s.dnn?.toLowerCase().includes(term) ||
                s.teids?.some(t => t.toLowerCase().includes(term))
            );
        }

        // 排序
        result.sort((a, b) => {
            let comparison = 0;

            switch (sortField) {
                case 'seid':
                    comparison = (a.seid || '').localeCompare(b.seid || '');
                    break;
                case 'ue_ip':
                    comparison = (a.ue_ip || '').localeCompare(b.ue_ip || '');
                    break;
                case 'packets':
                    const aPackets = (a.packets_ul || 0) + (a.packets_dl || 0);
                    const bPackets = (b.packets_ul || 0) + (b.packets_dl || 0);
                    comparison = aPackets - bPackets;
                    break;
                case 'created_at':
                    comparison = (a.created_at || '').localeCompare(b.created_at || '');
                    break;
            }

            return sortDirection === 'asc' ? comparison : -comparison;
        });

        return result;
    }, [sessions, searchTerm, sortField, sortDirection]);

    // 切換排序
    const toggleSort = (field: typeof sortField) => {
        if (sortField === field) {
            setSortDirection(d => d === 'asc' ? 'desc' : 'asc');
        } else {
            setSortField(field);
            setSortDirection('desc');
        }
    };

    if (isLoading && sessions.length === 0) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500" />
            </div>
        );
    }

    if (error && sessions.length === 0) {
        return (
            <div className="bg-red-500/20 text-red-400 p-4 rounded-lg text-center">
                {error}
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {/* 工具列 */}
            <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
                {/* 搜尋框 */}
                <div className="relative flex-1 max-w-md">
                    <input
                        type="text"
                        placeholder="搜尋 SEID, UE IP, SUPI, DNN, TEID..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className={`w-full rounded-lg pl-10 pr-4 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500 ${theme === 'dark'
                            ? 'bg-gray-700 text-white placeholder-gray-400'
                            : 'bg-gray-100 text-gray-900 placeholder-gray-500 border border-gray-300'
                            }`}
                    />
                    <svg
                        className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-500'}`}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                    >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </div>

                {/* 統計資訊 */}
                <div className="flex gap-4 text-sm">
                    <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
                        總共 <span className="text-cyan-400 font-bold">{sessions.length}</span> 個 Sessions
                    </span>
                    {searchTerm && (
                        <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>
                            符合 <span className="text-green-400 font-bold">{filteredAndSortedSessions.length}</span> 筆
                        </span>
                    )}
                </div>
            </div>

            {/* 排序按鈕 */}
            <div className="flex gap-2 flex-wrap">
                {[
                    { field: 'created_at' as const, label: '建立時間' },
                    { field: 'seid' as const, label: 'SEID' },
                    { field: 'ue_ip' as const, label: 'UE IP' },
                    { field: 'packets' as const, label: '封包數' },
                ].map(({ field, label }) => (
                    <button
                        key={field}
                        onClick={() => toggleSort(field)}
                        className={`px-3 py-1 rounded-lg text-sm transition-colors ${sortField === field
                            ? 'bg-cyan-600 text-white'
                            : theme === 'dark'
                                ? 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                            }`}
                    >
                        {label}
                        {sortField === field && (
                            <span className="ml-1">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                        )}
                    </button>
                ))}
            </div>

            {/* Session Cards */}
            {filteredAndSortedSessions.length === 0 ? (
                <div className={`rounded-lg p-8 text-center ${theme === 'dark' ? 'bg-gray-800/50' : 'bg-gray-100'}`}>
                    <div className={`text-lg mb-2 ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                        {searchTerm ? '🔍 沒有符合的 Sessions' : '📭 目前沒有活躍的 PDU Sessions'}
                    </div>
                    <p className={`text-sm ${theme === 'dark' ? 'text-gray-500' : 'text-gray-500'}`}>
                        {searchTerm
                            ? '請嘗試其他搜尋條件'
                            : '當 UE 建立 PDU Session 時會自動顯示在這裡'
                        }
                    </p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {filteredAndSortedSessions.map((session, index) => {
                        return (
                            <div
                                key={`${session.seid}-${index}`}
                                onClick={() => setSelectedSession(session)}
                                className={`rounded-xl p-4 cursor-pointer transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-cyan-500/10 border hover:border-cyan-500/50 ${theme === 'dark'
                                    ? 'bg-gray-800/80 hover:bg-gray-700/80 border-gray-700'
                                    : 'bg-white hover:bg-gray-50 border-gray-200'
                                    }`}
                            >
                                {/* Card Header */}
                                <div className="flex justify-between items-start mb-3">
                                    <div>
                                        <div className="text-cyan-400 font-bold text-lg">SEID: {session.seid}</div>
                                        <div className={`text-xs ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}`}>
                                            <span className="text-green-400">UL:</span> {session.teid_ul || session.teids?.[0] || 'N/A'} |
                                            <span className="text-blue-400"> DL:</span> {session.teid_dl || session.teids?.[1] || 'N/A'}
                                        </div>
                                    </div>
                                    <div className={`px-2 py-1 rounded-full text-xs ${session.status === 'Active'
                                        ? 'bg-green-500/20 text-green-400'
                                        : 'bg-gray-500/20 text-gray-400'
                                        }`}>
                                        {session.status === 'Active' ? '活躍' : session.status || '未知'}
                                    </div>
                                </div>

                                {/* Card Body */}
                                <div className="space-y-2 text-sm">
                                    <div className="flex justify-between">
                                        <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>UE IP:</span>
                                        <span className={`font-mono ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>{session.ue_ip || 'N/A'}</span>
                                    </div>
                                    {session.supi && (
                                        <div className="flex justify-between">
                                            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>SUPI:</span>
                                            <span className={`font-mono text-xs ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>{session.supi}</span>
                                        </div>
                                    )}
                                    {session.dnn && (
                                        <div className="flex justify-between">
                                            <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>DNN:</span>
                                            <span className={theme === 'dark' ? 'text-white' : 'text-gray-900'}>{session.dnn}</span>
                                        </div>
                                    )}

                                    <div className="flex justify-between">
                                        <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>封包:</span>
                                        <span className={theme === 'dark' ? 'text-white' : 'text-gray-900'}>
                                            ↑{(session.packets_ul || 0).toLocaleString()} / ↓{(session.packets_dl || 0).toLocaleString()}
                                        </span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className={theme === 'dark' ? 'text-gray-400' : 'text-gray-600'}>流量:</span>
                                        <span className={theme === 'dark' ? 'text-white' : 'text-gray-900'}>
                                            {formatBytes((session.bytes_ul || 0) + (session.bytes_dl || 0))}
                                        </span>
                                    </div>
                                </div>

                                {/* Card Footer */}
                                <div className={`mt-3 pt-3 border-t flex justify-between items-center ${theme === 'dark' ? 'border-gray-700' : 'border-gray-200'}`}>
                                    <span className={`text-xs ${theme === 'dark' ? 'text-gray-500' : 'text-gray-500'}`}>
                                        {session.duration || formatTimestamp(session.created_at)}
                                    </span>
                                    <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                    </svg>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Detail Modal */}
            {selectedSession && (
                <SessionDetailModal
                    session={selectedSession}
                    onClose={() => setSelectedSession(null)}
                    theme={theme}
                />
            )}
        </div>
    );
}
