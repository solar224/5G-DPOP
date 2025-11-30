import { useState, useMemo } from 'react'
import { DropStats, DropEvent, DROP_REASON_DATABASE, DropReasonInfo, SessionInfo } from '../services/api'

interface DropAlertPanelProps {
    drops: DropStats
    sessions?: SessionInfo[]
    theme?: 'dark' | 'light'
}

// Get color for drop reason based on severity
function getReasonColor(reason: string): string {
    const info = DROP_REASON_DATABASE[reason]
    if (!info) return 'bg-slate-500/20 text-slate-400'

    switch (info.severity) {
        case 'critical':
            return 'bg-red-500/20 text-red-400 border border-red-500/30'
        case 'warning':
            return 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
        case 'info':
            return 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
        default:
            return 'bg-slate-500/20 text-slate-400'
    }
}

// Get severity icon
function getSeverityIcon(severity: string): string {
    switch (severity) {
        case 'critical': return '🔴'
        case 'warning': return '🟡'
        case 'info': return '🔵'
        default: return '⚪'
    }
}

// Get layer badge color
function getLayerColor(layer: string): string {
    switch (layer) {
        case 'GTP': return 'bg-purple-500/20 text-purple-400'
        case 'PFCP': return 'bg-cyan-500/20 text-cyan-400'
        case 'Kernel': return 'bg-slate-500/20 text-slate-400'
        case 'QoS': return 'bg-green-500/20 text-green-400'
        case 'Routing': return 'bg-amber-500/20 text-amber-400'
        default: return 'bg-slate-500/20 text-slate-400'
    }
}

// Format packet length
function formatPktLen(len: number): string {
    if (len >= 1024) return `${(len / 1024).toFixed(1)} KB`
    return `${len} B`
}

// Get direction info
function getDirectionInfo(direction: string): { icon: string; label: string; path: string; color: string } {
    if (direction === 'uplink') {
        return {
            icon: '↑',
            label: 'Uplink',
            path: 'UE → gNB → UPF → DN',
            color: 'text-green-400'
        }
    }
    return {
        icon: '↓',
        label: 'Downlink',
        path: 'DN → UPF → gNB → UE',
        color: 'text-blue-400'
    }
}

// Correlate drop event with session
function correlateWithSession(drop: DropEvent, sessions: SessionInfo[]): SessionInfo | undefined {
    if (!sessions || sessions.length === 0) return undefined

    // Try to match by TEID first
    if (drop.teid && drop.teid !== '0x0' && drop.teid !== '0x00000000') {
        const teidValue = drop.teid.toLowerCase()
        for (const session of sessions) {
            if (session.teids?.some(t => t.toLowerCase() === teidValue)) {
                return session
            }
        }
    }

    // Try to match by UE IP
    if (drop.src_ip || drop.dst_ip) {
        for (const session of sessions) {
            if (session.ue_ip === drop.src_ip || session.ue_ip === drop.dst_ip) {
                return session
            }
        }
    }

    return undefined
}

// Generate raw log entry format (simulating kernel/agent log)
function generateRawLog(drop: DropEvent, reasonInfo?: DropReasonInfo): string {
    const ts = new Date(drop.timestamp).toISOString()
    const teid = drop.teid || 'N/A'
    const srcIp = drop.src_ip || '0.0.0.0'
    const dstIp = drop.dst_ip || '0.0.0.0'
    const srcPort = drop.src_port || 0
    const dstPort = drop.dst_port || 0
    const reasonCode = reasonInfo?.code || '?'

    return `[${ts}] [DROP] reason=${drop.reason}(${reasonCode}) direction=${drop.direction} ` +
        `teid=${teid} src=${srcIp}:${srcPort} dst=${dstIp}:${dstPort} len=${drop.pkt_len} ` +
        `layer=${reasonInfo?.layer || 'unknown'}`
}

export default function DropAlertPanel({ drops, sessions = [], theme = 'dark' }: DropAlertPanelProps) {
    const [selectedDropIndex, setSelectedDropIndex] = useState<number | null>(null)
    const [showAll, setShowAll] = useState(false)
    const [expandedReasons, setExpandedReasons] = useState<Set<string>>(new Set())
    const [viewMode, setViewMode] = useState<'timeline' | 'analysis'>('timeline')

    const hasDrops = drops.total > 0

    // Calculate max count for progress bar
    const maxReasonCount = Math.max(...Object.values(drops.by_reason || {}), 1)

    const displayDrops = showAll
        ? (drops.recent_drops || [])
        : (drops.recent_drops || []).slice(0, 5)

    // Aggregate statistics by reason with enriched data
    const reasonStats = useMemo(() => {
        const stats: Record<string, { count: number; percentage: number; info: DropReasonInfo | undefined }> = {}
        const totalDrops = drops.total || 1

        Object.entries(drops.by_reason || {}).forEach(([reason, count]) => {
            stats[reason] = {
                count,
                percentage: (count / totalDrops) * 100,
                info: DROP_REASON_DATABASE[reason]
            }
        })

        return stats
    }, [drops.by_reason, drops.total])

    // Theme-based styles
    const textPrimary = theme === 'dark' ? 'text-white' : 'text-gray-900'
    const textSecondary = theme === 'dark' ? 'text-slate-400' : 'text-gray-500'
    const textMuted = theme === 'dark' ? 'text-slate-500' : 'text-gray-400'
    const cardBg = theme === 'dark' ? 'bg-slate-800/30' : 'bg-gray-50'
    const cardBgHover = theme === 'dark' ? 'hover:bg-slate-700/50' : 'hover:bg-gray-100'
    const progressBg = theme === 'dark' ? 'bg-slate-700' : 'bg-gray-200'
    const borderColor = theme === 'dark' ? 'border-slate-700' : 'border-gray-200'
    const hoverBorder = theme === 'dark' ? 'hover:border-slate-600' : 'hover:border-gray-300'
    const codeBg = theme === 'dark' ? 'bg-slate-900' : 'bg-gray-100'

    const toggleReasonExpand = (reason: string) => {
        const newExpanded = new Set(expandedReasons)
        if (newExpanded.has(reason)) {
            newExpanded.delete(reason)
        } else {
            newExpanded.add(reason)
        }
        setExpandedReasons(newExpanded)
    }

    return (
        <div className="space-y-4">
            {/* Summary Header */}
            <div className={`p-4 rounded-lg ${hasDrops ? 'bg-red-500/10 border border-red-500/20' : 'bg-green-500/10 border border-green-500/20'}`}>
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <span className={`text-2xl ${hasDrops ? 'pulse-alert' : ''}`}>
                            {hasDrops ? '⚠️' : '✅'}
                        </span>
                        <div>
                            <div className={`font-semibold ${hasDrops ? 'text-red-400' : 'text-green-400'}`}>
                                {hasDrops ? `${drops.total.toLocaleString()} Drops Detected` : 'No Drops Detected'}
                            </div>
                            <div className={textSecondary}>
                                Drop Rate: {drops.rate_percent.toFixed(4)}% | {Object.keys(drops.by_reason || {}).length} unique reasons
                            </div>
                        </div>
                    </div>
                    {hasDrops && (
                        <div className="text-right">
                            <div className="text-2xl font-bold text-red-400">
                                {drops.rate_percent.toFixed(2)}%
                            </div>
                            <div className="text-xs text-slate-500">packet loss rate</div>
                        </div>
                    )}
                </div>
            </div>

            {/* View Mode Toggle */}
            {hasDrops && (
                <div className="flex gap-2">
                    <button
                        onClick={() => setViewMode('timeline')}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${viewMode === 'timeline'
                            ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                            : `${cardBg} ${textSecondary} ${hoverBorder} border ${borderColor}`
                            }`}
                    >
                        📋 Timeline View
                    </button>
                    <button
                        onClick={() => setViewMode('analysis')}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${viewMode === 'analysis'
                            ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                            : `${cardBg} ${textSecondary} ${hoverBorder} border ${borderColor}`
                            }`}
                    >
                        🔍 Root Cause Analysis
                    </button>
                </div>
            )}

            {/* Root Cause Analysis View */}
            {viewMode === 'analysis' && Object.keys(drops.by_reason || {}).length > 0 && (
                <div className="space-y-3">
                    <h3 className={`text-sm font-medium ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                        🔍 Drop Reasons Analysis
                    </h3>
                    {Object.entries(reasonStats)
                        .sort(([, a], [, b]) => b.count - a.count)
                        .map(([reason, { count, percentage, info }]) => (
                            <div
                                key={reason}
                                className={`rounded-lg border ${borderColor} overflow-hidden`}
                            >
                                {/* Reason Header */}
                                <div
                                    className={`p-3 cursor-pointer ${cardBg} ${cardBgHover} transition-colors`}
                                    onClick={() => toggleReasonExpand(reason)}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <span className="text-lg">{info ? getSeverityIcon(info.severity) : '⚪'}</span>
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className={`font-medium ${textPrimary}`}>{info?.name || reason}</span>
                                                    <span className={`text-xs px-2 py-0.5 rounded ${getLayerColor(info?.layer || '')}`}>
                                                        {info?.layer || 'Unknown'}
                                                    </span>
                                                </div>
                                                <div className={`text-xs ${textMuted} mt-0.5`}>
                                                    {info?.description?.substring(0, 80)}...
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <div className="text-right">
                                                <div className={`text-lg font-bold ${info?.severity === 'critical' ? 'text-red-400' : info?.severity === 'warning' ? 'text-orange-400' : 'text-blue-400'}`}>
                                                    {count.toLocaleString()}
                                                </div>
                                                <div className="text-xs text-slate-500">{percentage.toFixed(1)}%</div>
                                            </div>
                                            <span className={`transition-transform ${expandedReasons.has(reason) ? 'rotate-180' : ''}`}>
                                                ▼
                                            </span>
                                        </div>
                                    </div>
                                    {/* Progress Bar */}
                                    <div className={`mt-2 h-1.5 ${progressBg} rounded-full overflow-hidden`}>
                                        <div
                                            className={`h-full transition-all duration-500 ${info?.severity === 'critical' ? 'bg-gradient-to-r from-red-600 to-red-400' :
                                                info?.severity === 'warning' ? 'bg-gradient-to-r from-orange-600 to-orange-400' :
                                                    'bg-gradient-to-r from-blue-600 to-blue-400'
                                                }`}
                                            style={{ width: `${(count / maxReasonCount) * 100}%` }}
                                        />
                                    </div>
                                </div>

                                {/* Expanded Details */}
                                {expandedReasons.has(reason) && info && (
                                    <div className={`p-4 border-t ${borderColor} space-y-4`}>
                                        {/* Full Description */}
                                        <div>
                                            <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>Description</h4>
                                            <p className={`text-sm ${textSecondary}`}>{info.description}</p>
                                        </div>

                                        {/* Impact */}
                                        <div>
                                            <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>📊 Impact</h4>
                                            <p className={`text-sm ${textSecondary}`}>{info.impact}</p>
                                        </div>

                                        {/* Possible Causes */}
                                        <div>
                                            <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>🔎 Possible Causes</h4>
                                            <ul className="space-y-1">
                                                {info.possibleCauses.map((cause, idx) => (
                                                    <li key={idx} className={`text-sm ${textSecondary} flex items-start gap-2`}>
                                                        <span className="text-yellow-500 mt-0.5">•</span>
                                                        {cause}
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>

                                        {/* Suggested Actions */}
                                        <div>
                                            <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>🛠️ Suggested Actions</h4>
                                            <ul className="space-y-2">
                                                {info.suggestedActions.map((action, idx) => (
                                                    <li key={idx} className={`text-sm flex items-start gap-2`}>
                                                        <span className="text-green-500 font-bold">{idx + 1}.</span>
                                                        <span className={textSecondary}>
                                                            {action.includes(':') ? (
                                                                <>
                                                                    {action.split(':')[0]}:
                                                                    <code className={`ml-1 px-1.5 py-0.5 rounded ${codeBg} text-cyan-400 font-mono text-xs`}>
                                                                        {action.split(':').slice(1).join(':')}
                                                                    </code>
                                                                </>
                                                            ) : (
                                                                action
                                                            )}
                                                        </span>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>

                                        {/* Technical Details */}
                                        <div className={`p-3 rounded-lg ${codeBg} border ${borderColor}`}>
                                            <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>📝 Technical Details</h4>
                                            <div className="grid grid-cols-2 gap-2 text-xs">
                                                <div>
                                                    <span className={textMuted}>Reason Code:</span>
                                                    <span className="ml-2 font-mono text-cyan-400">{info.code}</span>
                                                </div>
                                                <div>
                                                    <span className={textMuted}>Layer:</span>
                                                    <span className="ml-2 font-mono text-cyan-400">{info.layer}</span>
                                                </div>
                                                <div>
                                                    <span className={textMuted}>Severity:</span>
                                                    <span className={`ml-2 font-mono ${info.severity === 'critical' ? 'text-red-400' : info.severity === 'warning' ? 'text-orange-400' : 'text-blue-400'}`}>
                                                        {info.severity.toUpperCase()}
                                                    </span>
                                                </div>
                                                <div>
                                                    <span className={textMuted}>Occurrences:</span>
                                                    <span className="ml-2 font-mono text-cyan-400">{count.toLocaleString()}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                </div>
            )}

            {/* Timeline View - Recent Drop Events */}
            {viewMode === 'timeline' && (
                <div>
                    <div className="flex items-center justify-between mb-2">
                        <h3 className={`text-sm font-medium ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                            📋 Recent Drop Events Timeline
                        </h3>
                        {(drops.recent_drops?.length || 0) > 5 && (
                            <button
                                onClick={() => setShowAll(!showAll)}
                                className="text-xs text-cyan-400 hover:text-cyan-300"
                            >
                                {showAll ? 'Show Less' : `Show All (${drops.recent_drops?.length})`}
                            </button>
                        )}
                    </div>

                    {!drops.recent_drops || drops.recent_drops.length === 0 ? (
                        <div className={`text-center py-6 ${textMuted} text-sm ${cardBg} rounded-lg`}>
                            <p>No recent drop events</p>
                            <p className="text-xs mt-1">Network is running smoothly</p>
                        </div>
                    ) : (
                        <div className="space-y-2 max-h-[600px] overflow-y-auto">
                            {displayDrops.map((drop, idx) => {
                                const reasonInfo = DROP_REASON_DATABASE[drop.reason]
                                const dirInfo = getDirectionInfo(drop.direction)
                                const correlatedSession = correlateWithSession(drop, sessions)
                                const rawLog = generateRawLog(drop, reasonInfo)

                                return (
                                    <div
                                        key={idx}
                                        className={`rounded-lg border transition-all ${selectedDropIndex === idx
                                            ? `${theme === 'dark' ? 'bg-slate-700/50' : 'bg-gray-100'} border-cyan-500`
                                            : `${cardBg} ${borderColor} ${hoverBorder}`
                                            }`}
                                    >
                                        {/* Event Header - Always Visible */}
                                        <div
                                            className="p-3 cursor-pointer"
                                            onClick={() => setSelectedDropIndex(selectedDropIndex === idx ? null : idx)}
                                        >
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-3">
                                                    <div className="flex flex-col items-center">
                                                        <span className={`text-lg ${dirInfo.color}`}>{dirInfo.icon}</span>
                                                        <span className="text-xs text-slate-500">{dirInfo.label}</span>
                                                    </div>
                                                    <div>
                                                        <div className="flex items-center gap-2 flex-wrap">
                                                            <span className={`text-xs px-2 py-0.5 rounded ${getReasonColor(drop.reason)}`}>
                                                                {reasonInfo ? getSeverityIcon(reasonInfo.severity) : '⚪'} {drop.reason}
                                                            </span>
                                                            {reasonInfo && (
                                                                <span className={`text-xs px-2 py-0.5 rounded ${getLayerColor(reasonInfo.layer)}`}>
                                                                    {reasonInfo.layer}
                                                                </span>
                                                            )}
                                                        </div>
                                                        <div className={`text-xs ${textMuted} mt-1`}>
                                                            {new Date(drop.timestamp).toLocaleString()} | TEID: <span className="font-mono text-cyan-400">{drop.teid}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-3">
                                                    <div className="text-right">
                                                        <div className={`text-sm font-mono ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                                                            {formatPktLen(drop.pkt_len)}
                                                        </div>
                                                        {correlatedSession && (
                                                            <div className="text-xs text-green-400">📱 Session Found</div>
                                                        )}
                                                    </div>
                                                    <span className={`transition-transform text-slate-500 ${selectedDropIndex === idx ? 'rotate-180' : ''}`}>
                                                        ▼
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Expanded Details */}
                                        {selectedDropIndex === idx && (
                                            <div className={`border-t ${borderColor}`}>
                                                {/* Connection Path Visualization */}
                                                <div className={`p-4 ${codeBg}`}>
                                                    <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-3`}>
                                                        🔗 Connection Path (Drop Point: {reasonInfo?.layer || 'Unknown'})
                                                    </h4>
                                                    <div className="flex items-center justify-center gap-2 text-sm">
                                                        {drop.direction === 'uplink' ? (
                                                            <>
                                                                <div className={`px-3 py-2 rounded ${cardBg} border ${borderColor}`}>
                                                                    <div className="text-xs text-slate-500">Source (UE)</div>
                                                                    <div className="font-mono text-green-400">{drop.src_ip || 'Unknown'}</div>
                                                                    {drop.src_port && <div className="text-xs text-slate-500">:{drop.src_port}</div>}
                                                                </div>
                                                                <span className="text-green-400">→</span>
                                                                <div className={`px-3 py-2 rounded border-2 ${reasonInfo?.layer === 'GTP' || reasonInfo?.layer === 'PFCP' ? 'border-red-500 bg-red-500/10' : `${cardBg} ${borderColor}`}`}>
                                                                    <div className="text-xs text-slate-500">UPF</div>
                                                                    <div className="font-mono text-purple-400">{correlatedSession?.upf_ip || 'N/A'}</div>
                                                                    {reasonInfo?.layer === 'GTP' || reasonInfo?.layer === 'PFCP' ? (
                                                                        <div className="text-xs text-red-400">❌ DROP HERE</div>
                                                                    ) : null}
                                                                </div>
                                                                <span className="text-blue-400">→</span>
                                                                <div className={`px-3 py-2 rounded border ${reasonInfo?.layer === 'Routing' ? 'border-red-500 bg-red-500/10' : `${cardBg} ${borderColor}`}`}>
                                                                    <div className="text-xs text-slate-500">Destination (DN)</div>
                                                                    <div className="font-mono text-blue-400">{drop.dst_ip || 'Unknown'}</div>
                                                                    {drop.dst_port && <div className="text-xs text-slate-500">:{drop.dst_port}</div>}
                                                                    {reasonInfo?.layer === 'Routing' ? (
                                                                        <div className="text-xs text-red-400">❌ DROP HERE</div>
                                                                    ) : null}
                                                                </div>
                                                            </>
                                                        ) : (
                                                            <>
                                                                <div className={`px-3 py-2 rounded ${cardBg} border ${borderColor}`}>
                                                                    <div className="text-xs text-slate-500">Source (DN)</div>
                                                                    <div className="font-mono text-blue-400">{drop.src_ip || 'Unknown'}</div>
                                                                    {drop.src_port && <div className="text-xs text-slate-500">:{drop.src_port}</div>}
                                                                </div>
                                                                <span className="text-blue-400">→</span>
                                                                <div className={`px-3 py-2 rounded border-2 ${reasonInfo?.layer === 'GTP' || reasonInfo?.layer === 'PFCP' ? 'border-red-500 bg-red-500/10' : `${cardBg} ${borderColor}`}`}>
                                                                    <div className="text-xs text-slate-500">UPF</div>
                                                                    <div className="font-mono text-purple-400">{correlatedSession?.upf_ip || 'N/A'}</div>
                                                                    {reasonInfo?.layer === 'GTP' || reasonInfo?.layer === 'PFCP' ? (
                                                                        <div className="text-xs text-red-400">❌ DROP HERE</div>
                                                                    ) : null}
                                                                </div>
                                                                <span className="text-green-400">→</span>
                                                                <div className={`px-3 py-2 rounded ${cardBg} border ${borderColor}`}>
                                                                    <div className="text-xs text-slate-500">Destination (UE)</div>
                                                                    <div className="font-mono text-green-400">{drop.dst_ip || 'Unknown'}</div>
                                                                    {drop.dst_port && <div className="text-xs text-slate-500">:{drop.dst_port}</div>}
                                                                </div>
                                                            </>
                                                        )}
                                                    </div>
                                                </div>

                                                {/* Reason Explanation */}
                                                {reasonInfo && (
                                                    <div className={`p-4 border-t ${borderColor}`}>
                                                        <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>
                                                            ❓ Why This Drop Occurred
                                                        </h4>
                                                        <p className={`text-sm ${textSecondary}`}>{reasonInfo.description}</p>
                                                        <div className={`mt-2 p-2 rounded ${reasonInfo.severity === 'critical' ? 'bg-red-500/10' : reasonInfo.severity === 'warning' ? 'bg-orange-500/10' : 'bg-blue-500/10'}`}>
                                                            <span className="text-xs font-medium">Impact: </span>
                                                            <span className={`text-xs ${textSecondary}`}>{reasonInfo.impact}</span>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Session Correlation */}
                                                {correlatedSession && (
                                                    <div className={`p-4 border-t ${borderColor}`}>
                                                        <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>
                                                            📱 Correlated Session
                                                        </h4>
                                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                                            <div>
                                                                <span className={textMuted}>SEID:</span>
                                                                <div className="font-mono text-cyan-400">{correlatedSession.seid}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>UE IP:</span>
                                                                <div className="font-mono text-green-400">{correlatedSession.ue_ip}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>SUPI:</span>
                                                                <div className="font-mono text-purple-400">{correlatedSession.supi || 'N/A'}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>DNN:</span>
                                                                <div className="font-mono text-amber-400">{correlatedSession.dnn || 'N/A'}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>gNB IP:</span>
                                                                <div className="font-mono text-blue-400">{correlatedSession.gnb_ip || 'N/A'}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>UPF IP:</span>
                                                                <div className="font-mono text-purple-400">{correlatedSession.upf_ip || 'N/A'}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>QFI:</span>
                                                                <div className="font-mono text-cyan-400">{correlatedSession.qfi ?? 'N/A'}</div>
                                                            </div>
                                                            <div>
                                                                <span className={textMuted}>Status:</span>
                                                                <div className={`font-medium ${correlatedSession.status === 'Active' ? 'text-green-400' : 'text-yellow-400'}`}>
                                                                    {correlatedSession.status}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Quick Actions */}
                                                {reasonInfo && (
                                                    <div className={`p-4 border-t ${borderColor}`}>
                                                        <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>
                                                            🛠️ Quick Actions
                                                        </h4>
                                                        <div className="flex flex-wrap gap-2">
                                                            {reasonInfo.suggestedActions.slice(0, 3).map((action, actionIdx) => {
                                                                const command = action.includes(':') ? action.split(':').slice(1).join(':').trim() : null
                                                                return (
                                                                    <div
                                                                        key={actionIdx}
                                                                        className={`px-3 py-2 rounded text-xs ${cardBg} border ${borderColor}`}
                                                                    >
                                                                        {command ? (
                                                                            <>
                                                                                <div className={textSecondary}>{action.split(':')[0]}</div>
                                                                                <code className="font-mono text-cyan-400">{command}</code>
                                                                            </>
                                                                        ) : (
                                                                            <span className={textSecondary}>{action}</span>
                                                                        )}
                                                                    </div>
                                                                )
                                                            })}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Raw Log */}
                                                <div className={`p-4 border-t ${borderColor}`}>
                                                    <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>
                                                        📜 Raw Agent Log
                                                    </h4>
                                                    <pre className={`p-3 rounded text-xs font-mono ${codeBg} overflow-x-auto whitespace-pre-wrap break-all text-slate-300`}>
                                                        {rawLog}
                                                    </pre>
                                                </div>

                                                {/* Packet Details */}
                                                <div className={`p-4 border-t ${borderColor}`}>
                                                    <h4 className={`text-xs font-semibold uppercase tracking-wider ${textMuted} mb-2`}>
                                                        📦 Packet Details
                                                    </h4>
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                                                        <div>
                                                            <span className={textMuted}>TEID:</span>
                                                            <div className="font-mono text-cyan-400">{drop.teid}</div>
                                                        </div>
                                                        <div>
                                                            <span className={textMuted}>Source IP:</span>
                                                            <div className="font-mono text-green-400">{drop.src_ip}</div>
                                                        </div>
                                                        <div>
                                                            <span className={textMuted}>Dest IP:</span>
                                                            <div className="font-mono text-blue-400">{drop.dst_ip}</div>
                                                        </div>
                                                        <div>
                                                            <span className={textMuted}>Packet Size:</span>
                                                            <div className="font-mono text-purple-400">{drop.pkt_len} bytes</div>
                                                        </div>
                                                        {drop.src_port && (
                                                            <div>
                                                                <span className={textMuted}>Source Port:</span>
                                                                <div className="font-mono text-amber-400">{drop.src_port}</div>
                                                            </div>
                                                        )}
                                                        {drop.dst_port && (
                                                            <div>
                                                                <span className={textMuted}>Dest Port:</span>
                                                                <div className="font-mono text-amber-400">{drop.dst_port}</div>
                                                            </div>
                                                        )}
                                                        <div>
                                                            <span className={textMuted}>Direction:</span>
                                                            <div className={dirInfo.color}>{dirInfo.path}</div>
                                                        </div>
                                                        <div>
                                                            <span className={textMuted}>Timestamp:</span>
                                                            <div className="font-mono text-slate-400">{new Date(drop.timestamp).toISOString()}</div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )
                            })}
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}
