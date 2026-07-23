import { TrafficStats, DropStats, SessionInfo } from '../services/api'
import TrafficChart from './TrafficChart'
import DropAlertPanel from './DropAlertPanel'
import SessionTable from './SessionTable'
import SessionTrafficChart from './SessionTrafficChart'
import Topology from './Topology'
import { formatEnglishTime } from '../utils/dateTime'
import { formatBytes, formatMbps, selectBitRateUnit } from '../utils/units'

type Theme = 'dark' | 'light'

interface DashboardProps {
    metrics: TrafficStats
    drops: DropStats
    sessions: SessionInfo[]
    theme: Theme
}

function formatNumber(n: number): string {
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
    return n.toString()
}

function formatThroughput(mbps: number): { value: string; unit: string } {
    const bitsPerSecond = mbps * 1_000_000
    const scale = selectBitRateUnit(bitsPerSecond)
    const value = bitsPerSecond / scale.divisor
    return {
        value: value.toFixed(scale.unit === 'bps' ? 0 : 2),
        unit: scale.unit,
    }
}

export default function Dashboard({ metrics, drops, sessions, theme }: DashboardProps) {
    const uplinkTp = formatThroughput(metrics.uplink.throughput_mbps)
    const downlinkTp = formatThroughput(metrics.downlink.throughput_mbps)

    const totalPackets = metrics.uplink.packets + metrics.downlink.packets
    const totalBytes = metrics.uplink.bytes + metrics.downlink.bytes
    const activeSessions = sessions.filter(session => session.monitoring_state === 'active')
    const observedTEIDs = new Set(
        activeSessions.flatMap(session => [
            ...(session.local_f_teids || []).map(teid => `${session.observation_id}:local:${teid}`),
            ...(session.flow_rules || [])
                .filter(rule => Boolean(rule.outer_teid))
                .map(rule => `${session.observation_id}:remote:${rule.outer_teid}`),
        ])
    ).size

    const cardBg = theme === 'dark' ? 'bg-slate-800/50' : 'bg-white'
    const cardBorder = theme === 'dark' ? 'border-slate-700' : 'border-gray-200'
    const textPrimary = theme === 'dark' ? 'text-white' : 'text-gray-900'
    const textSecondary = theme === 'dark' ? 'text-slate-400' : 'text-gray-500'
    const textMuted = theme === 'dark' ? 'text-slate-500' : 'text-gray-400'
    const textValue = theme === 'dark' ? 'text-slate-300' : 'text-gray-700'
    const progressBg = theme === 'dark' ? 'bg-slate-700' : 'bg-gray-200'

    return (
        <div className="space-y-6 pb-16">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className={`${cardBg} rounded-xl p-5 border ${cardBorder} hover:border-green-500/50 transition-colors`}>
                    <div className="flex items-center justify-between mb-3">
                        <span className={`${textSecondary} text-sm`}>Uplink Traffic</span>
                        <span className="text-green-400 text-xs font-medium px-2 py-0.5 bg-green-500/20 rounded-full">↑ UL</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className={`text-3xl font-bold ${textPrimary}`}>{uplinkTp.value}</span>
                        <span className={`text-lg ${textSecondary}`}>{uplinkTp.unit}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className={`${textMuted} text-xs`}>Total packets</div>
                            <div className="text-green-400 font-mono">{formatNumber(metrics.uplink.packets)}</div>
                        </div>
                        <div>
                            <div className={`${textMuted} text-xs`}>PDU bytes</div>
                            <div className={`${textValue} font-mono`}>{formatBytes(metrics.uplink.bytes)}</div>
                        </div>
                    </div>
                    <div className="mt-3">
                        <div className={`h-1.5 ${progressBg} rounded-full overflow-hidden`}>
                            <div
                                className="h-full bg-gradient-to-r from-green-500 to-green-400 transition-all duration-500"
                                style={{ width: `${totalBytes > 0 ? (metrics.uplink.bytes / totalBytes) * 100 : 0}%` }}
                            />
                        </div>
                        <div className={`text-xs ${textMuted} mt-1`}>
                            {totalBytes > 0 ? ((metrics.uplink.bytes / totalBytes) * 100).toFixed(1) : '0.0'}% of total
                        </div>
                    </div>
                </div>

                <div className={`${cardBg} rounded-xl p-5 border ${cardBorder} hover:border-blue-500/50 transition-colors`}>
                    <div className="flex items-center justify-between mb-3">
                        <span className={`${textSecondary} text-sm`}>Downlink Traffic</span>
                        <span className="text-blue-400 text-xs font-medium px-2 py-0.5 bg-blue-500/20 rounded-full">↓ DL</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className={`text-3xl font-bold ${textPrimary}`}>{downlinkTp.value}</span>
                        <span className={`text-lg ${textSecondary}`}>{downlinkTp.unit}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className={`${textMuted} text-xs`}>Total packets</div>
                            <div className="text-blue-400 font-mono">{formatNumber(metrics.downlink.packets)}</div>
                        </div>
                        <div>
                            <div className={`${textMuted} text-xs`}>PDU bytes</div>
                            <div className={`${textValue} font-mono`}>{formatBytes(metrics.downlink.bytes)}</div>
                        </div>
                    </div>
                    <div className="mt-3">
                        <div className={`h-1.5 ${progressBg} rounded-full overflow-hidden`}>
                            <div
                                className="h-full bg-gradient-to-r from-blue-500 to-blue-400 transition-all duration-500"
                                style={{ width: `${totalBytes > 0 ? (metrics.downlink.bytes / totalBytes) * 100 : 0}%` }}
                            />
                        </div>
                        <div className={`text-xs ${textMuted} mt-1`}>
                            {totalBytes > 0 ? ((metrics.downlink.bytes / totalBytes) * 100).toFixed(1) : '0.0'}% of total
                        </div>
                    </div>
                </div>

                <div className={`${cardBg} rounded-xl p-5 border transition-colors ${drops.rate_percent > 1
                    ? 'border-red-500 pulse-alert'
                    : drops.rate_percent > 0
                        ? 'border-yellow-500/50'
                        : `${cardBorder} hover:border-green-500/50`
                    }`}>
                    <div className="flex items-center justify-between mb-3">
                        <span className={`${textSecondary} text-sm`}>User-plane Drop Event Ratio</span>
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${drops.rate_percent > 1
                            ? 'text-red-400 bg-red-500/20'
                            : drops.rate_percent > 0
                                ? 'text-yellow-400 bg-yellow-500/20'
                                : 'text-green-400 bg-green-500/20'
                            }`}>
                            {drops.rate_percent > 1 ? '⚠️ Critical' : drops.rate_percent > 0 ? '⚠️ Warning' : '✓ OK'}
                        </span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className={`text-3xl font-bold ${drops.rate_percent > 0 ? 'text-red-400' : textPrimary
                            }`}>
                            {drops.rate_percent.toFixed(3)}
                        </span>
                        <span className={`text-lg ${textSecondary}`}>%</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className={`${textMuted} text-xs`}>User-plane</div>
                            <div className="text-red-400 font-mono">{formatNumber(drops.user_plane_total)}</div>
                        </div>
                        <div>
                            <div className={`${textMuted} text-xs`}>Infrastructure</div>
                            <div className={`${textValue} font-mono`}>{formatNumber(drops.infrastructure_total)}</div>
                        </div>
                    </div>
                    {Object.keys(drops.by_reason || {}).length > 0 && (
                        <div className="mt-3 flex gap-1">
                            {Object.entries(drops.by_reason).slice(0, 3).map(([reason, count], idx) => (
                                <div
                                    key={reason}
                                    className="flex-1 h-1.5 rounded-full"
                                    style={{
                                        backgroundColor: ['#ef4444', '#f97316', '#eab308'][idx],
                                        opacity: 0.5 + (count / drops.total) * 0.5
                                    }}
                                    title={`${reason}: ${count}`}
                                />
                            ))}
                        </div>
                    )}
                </div>

                <div className={`${cardBg} rounded-xl p-5 border ${cardBorder} hover:border-cyan-500/50 transition-colors`}>
                    <div className="flex items-center justify-between mb-3">
                        <span className={`${textSecondary} text-sm`}>Active Sessions</span>
                        <span className="text-cyan-400 text-xs font-medium px-2 py-0.5 bg-cyan-500/20 rounded-full">PDU</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className={`text-3xl font-bold ${textPrimary}`}>{activeSessions.length}</span>
                        <span className={`text-lg ${textSecondary}`}>sessions</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className={`${textMuted} text-xs`}>TEIDs</div>
                            <div className="text-purple-400 font-mono">{observedTEIDs}</div>
                        </div>
                        <div>
                            <div className={`${textMuted} text-xs`}>UE IPs</div>
                            <div className={`${textValue} font-mono`}>{new Set(activeSessions.map(s => s.ue_ip).filter(Boolean)).size}</div>
                        </div>
                    </div>
                    <div className="mt-3 flex gap-1">
                        {activeSessions.slice(0, 8).map((s, idx) => (
                            <div
                                key={idx}
                                className="w-2 h-2 bg-cyan-400 rounded-full"
                                title={`${s.observation_id}${s.ue_ip ? `: ${s.ue_ip}` : ''}`}
                            />
                        ))}
                        {activeSessions.length > 8 && (
                            <span className={`text-xs ${textMuted}`}>+{activeSessions.length - 8}</span>
                        )}
                    </div>
                </div>
            </div>

            <div className={`${cardBg} rounded-xl p-4 border ${cardBorder} flex flex-wrap justify-center gap-8`}>
                <div className="text-center">
                    <div className={`text-sm ${textMuted}`}>Total Packets</div>
                    <div className={`text-xl font-bold ${textPrimary}`}>{formatNumber(totalPackets)}</div>
                </div>
                <div className="text-center">
                    <div className={`text-sm ${textMuted}`}>Total PDU Bytes</div>
                    <div className={`text-xl font-bold ${textPrimary}`}>{formatBytes(totalBytes)}</div>
                </div>
                <div className="text-center">
                    <div className={`text-sm ${textMuted}`}>Combined Throughput</div>
                    <div className={`text-xl font-bold ${textPrimary}`}>
                        {formatMbps(metrics.uplink.throughput_mbps + metrics.downlink.throughput_mbps)}
                    </div>
                </div>
                {metrics.uplink.last_updated && (
                    <div className="text-center">
                        <div className={`text-sm ${textMuted}`}>Last Updated</div>
                        <div className={`text-sm ${textValue}`}>
                            {formatEnglishTime(metrics.uplink.last_updated)}
                        </div>
                    </div>
                )}
            </div>

            <div className={`${cardBg} rounded-xl p-5 border ${cardBorder}`}>
                <h2 className={`text-lg font-semibold ${textPrimary} mb-4`}>Live Traffic (Last 60s)</h2>
                <TrafficChart metrics={metrics} theme={theme} />
            </div>

            <div className={`${cardBg} rounded-xl p-5 border ${cardBorder}`}>
                <div className="flex items-center justify-between mb-4">
                    <h2 className={`text-lg font-semibold ${textPrimary}`}>Per-Session Traffic Analysis</h2>
                    <span className={`text-sm ${textSecondary}`}>
                        {sessions.length} observed session{sessions.length !== 1 ? 's' : ''}
                    </span>
                </div>
                <SessionTrafficChart sessions={sessions} theme={theme} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className={`${cardBg} rounded-xl p-5 border ${cardBorder}`}>
                    <h2 className={`text-lg font-semibold ${textPrimary} mb-4`}>Drop Events</h2>
                    <DropAlertPanel drops={drops} sessions={sessions} theme={theme} />
                </div>

                <div className={`${cardBg} rounded-xl p-5 border ${cardBorder}`}>
                    <h2 className={`text-lg font-semibold ${textPrimary} mb-1`}>Observed PDU Sessions</h2>
                    <p className={`text-xs ${textSecondary} mb-4`}>
                        PFCP endpoint identities and PDR/FAR tunnel evidence
                    </p>
                    <SessionTable theme={theme} />
                </div>
            </div>

            <div className={`${cardBg} rounded-xl p-5 border ${cardBorder}`}>
                <h2 className={`text-lg font-semibold ${textPrimary} mb-4`}>Network Topology</h2>
                <Topology sessions={sessions} drops={drops} theme={theme} />
            </div>
        </div>
    )
}
