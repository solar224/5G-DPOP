import { SessionInfo, DropStats } from '../services/api'

interface TopologyProps {
    sessions: SessionInfo[]
    drops: DropStats
}

export default function Topology({ sessions, drops }: TopologyProps) {
    const hasDrops = drops.total > 0
    const hasActiveSessions = sessions.length > 0

    // Calculate totals
    const totalUL = sessions.reduce((acc, s) => acc + s.packets_ul, 0)
    const totalDL = sessions.reduce((acc, s) => acc + s.packets_dl, 0)
    const totalTEIDs = sessions.reduce((acc, s) => acc + s.teids.length, 0)

    return (
        <div className="space-y-6">
            {/* Main Topology View */}
            <div className="flex items-center justify-center py-6">
                <div className="flex items-center gap-2 md:gap-4 flex-wrap justify-center">
                    {/* UE */}
                    <div className="flex flex-col items-center">
                        <div className={`w-16 h-16 md:w-20 md:h-20 rounded-xl flex items-center justify-center text-2xl md:text-3xl transition-all ${hasActiveSessions
                            ? 'bg-green-500/20 border-2 border-green-500 shadow-lg shadow-green-500/20'
                            : 'bg-slate-700 border-2 border-slate-600'
                            }`}>
                            📱
                        </div>
                        <span className="mt-2 text-sm font-medium text-slate-300">UE</span>
                        {sessions.length > 0 && (
                            <span className="text-xs text-cyan-400 font-mono">{sessions[0]?.ue_ip}</span>
                        )}
                        {sessions.length > 1 && (
                            <span className="text-xs text-slate-500">+{sessions.length - 1} more</span>
                        )}
                    </div>

                    {/* Connection Line UE -> gNB */}
                    <div className="flex items-center">
                        <div className={`w-8 md:w-12 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-green-500 to-green-400' : 'bg-slate-600'}`} />
                        <div className="flex flex-col items-center px-1 md:px-2">
                            <span className="text-slate-500 text-xs">N1/N2</span>
                        </div>
                        <div className={`w-8 md:w-12 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-green-400 to-green-500' : 'bg-slate-600'}`} />
                    </div>

                    {/* gNB */}
                    <div className="flex flex-col items-center">
                        <div className={`w-16 h-16 md:w-20 md:h-20 rounded-xl flex items-center justify-center text-2xl md:text-3xl transition-all ${hasActiveSessions
                            ? 'bg-green-500/20 border-2 border-green-500 shadow-lg shadow-green-500/20'
                            : 'bg-slate-700 border-2 border-slate-600'
                            }`}>
                            📡
                        </div>
                        <span className="mt-2 text-sm font-medium text-slate-300">gNB</span>
                        <span className="text-xs text-slate-500">UERANSIM</span>
                    </div>

                    {/* Connection Line gNB -> UPF (N3 GTP-U) */}
                    <div className="flex items-center relative">
                        <div className={`w-8 md:w-16 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-green-500 to-cyan-500' : 'bg-slate-600'}`}>
                            {/* Animated packet dots */}
                            {hasActiveSessions && (
                                <>
                                    <div className="absolute top-1/2 -translate-y-1/2 w-2 h-2 bg-green-400 rounded-full animate-ping" />
                                    <div className="absolute top-1/2 -translate-y-1/2 w-2 h-2 bg-green-400 rounded-full animate-pulse" style={{ animationDelay: '0.5s', left: '50%' }} />
                                </>
                            )}
                        </div>
                        <div className="flex flex-col items-center px-1 md:px-2">
                            <span className="text-cyan-400 text-xs font-medium">N3</span>
                            <span className="text-slate-500 text-xs">GTP-U</span>
                            {totalTEIDs > 0 && (
                                <span className="text-xs text-cyan-400">{totalTEIDs} TEIDs</span>
                            )}
                        </div>
                        <div className={`w-8 md:w-16 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-cyan-500 to-blue-500' : 'bg-slate-600'}`} />
                    </div>

                    {/* UPF - Main Focus */}
                    <div className="flex flex-col items-center relative">
                        {/* eBPF indicator - moved to top */}
                        <div className="absolute -top-6 left-1/2 -translate-x-1/2">
                            <span className="text-xs bg-purple-500/30 text-purple-400 px-2 py-0.5 rounded-full">
                                eBPF
                            </span>
                        </div>
                        <div className={`w-20 h-20 md:w-24 md:h-24 rounded-xl flex flex-col items-center justify-center border-2 transition-all ${hasDrops
                            ? 'bg-red-500/20 border-red-500 pulse-alert shadow-lg shadow-red-500/30'
                            : hasActiveSessions
                                ? 'bg-blue-500/20 border-blue-500 shadow-lg shadow-blue-500/20'
                                : 'bg-slate-700 border-slate-600'
                            }`}>
                            <span className="text-3xl md:text-4xl">🖥️</span>
                            {hasActiveSessions && (
                                <div className="flex gap-1 mt-1">
                                    <span className="text-xs text-green-400">↑{totalUL}</span>
                                    <span className="text-xs text-blue-400">↓{totalDL}</span>
                                </div>
                            )}
                        </div>
                        <span className="mt-2 text-sm font-bold text-white">UPF</span>
                        <span className="text-xs text-slate-400">free5GC + gtp5g</span>
                        {hasDrops && (
                            <div className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full px-2 py-0.5 animate-bounce">
                                ⚠️ {drops.total}
                            </div>
                        )}
                    </div>

                    {/* Connection Line UPF -> DN (N6) */}
                    <div className="flex items-center">
                        <div className={`w-8 md:w-12 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-blue-500 to-green-500' : 'bg-slate-600'}`} />
                        <div className="flex flex-col items-center px-1 md:px-2">
                            <span className="text-slate-500 text-xs">N6</span>
                        </div>
                        <div className={`w-8 md:w-12 h-1 ${hasActiveSessions ? 'bg-gradient-to-r from-green-500 to-green-400' : 'bg-slate-600'}`} />
                    </div>

                    {/* DN */}
                    <div className="flex flex-col items-center">
                        <div className={`w-16 h-16 md:w-20 md:h-20 rounded-xl flex items-center justify-center text-2xl md:text-3xl transition-all ${hasActiveSessions
                            ? 'bg-green-500/20 border-2 border-green-500 shadow-lg shadow-green-500/20'
                            : 'bg-slate-700 border-2 border-slate-600'
                            }`}>
                            🌐
                        </div>
                        <span className="mt-2 text-sm font-medium text-slate-300">DN</span>
                        <span className="text-xs text-slate-500">Internet</span>
                    </div>
                </div>
            </div>

            {/* Legend & Status */}
            <div className="flex flex-wrap justify-center gap-4 text-xs">
                <div className="flex items-center gap-2">
                    <span className="w-3 h-3 bg-green-500 rounded-full"></span>
                    <span className="text-slate-400">Active Connection</span>
                </div>
                <div className="flex items-center gap-2">
                    <span className="w-3 h-3 bg-cyan-500 rounded-full"></span>
                    <span className="text-slate-400">GTP-U Tunnel</span>
                </div>
                <div className="flex items-center gap-2">
                    <span className="w-3 h-3 bg-red-500 rounded-full"></span>
                    <span className="text-slate-400">Packet Drop</span>
                </div>
                <div className="flex items-center gap-2">
                    <span className="w-3 h-3 bg-purple-500 rounded-full"></span>
                    <span className="text-slate-400">eBPF Monitoring</span>
                </div>
            </div>

            {/* Connection Details */}
            {hasActiveSessions && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                    <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-cyan-400">{sessions.length}</div>
                        <div className="text-xs text-slate-500">PDU Sessions</div>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-purple-400">{totalTEIDs}</div>
                        <div className="text-xs text-slate-500">Active TEIDs</div>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-green-400">{totalUL.toLocaleString()}</div>
                        <div className="text-xs text-slate-500">Uplink Packets</div>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                        <div className="text-2xl font-bold text-blue-400">{totalDL.toLocaleString()}</div>
                        <div className="text-xs text-slate-500">Downlink Packets</div>
                    </div>
                </div>
            )}
        </div>
    )
}
