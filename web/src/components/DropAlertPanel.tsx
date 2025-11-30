import { useState } from 'react'
import { DropStats } from '../services/api'

interface DropAlertPanelProps {
    drops: DropStats
}

// Get color for drop reason
function getReasonColor(reason: string): string {
    const colors: Record<string, string> = {
        // Critical - Red tones
        'INVALID_TEID': 'bg-red-500/20 text-red-400',
        'NO_PDR_MATCH': 'bg-red-600/20 text-red-300',
        'NO_GTP_TUNNEL': 'bg-red-700/20 text-red-400',

        // Warning - Orange/Yellow tones
        'QOS_VIOLATION': 'bg-orange-500/20 text-orange-400',
        'POLICY_DROP': 'bg-orange-600/20 text-orange-300',
        'NO_FAR_ACTION': 'bg-yellow-500/20 text-yellow-400',

        // Network issues - Purple/Pink tones
        'BUFFER_OVERFLOW': 'bg-purple-500/20 text-purple-400',
        'MEMORY_ERROR': 'bg-purple-600/20 text-purple-300',
        'MTU_EXCEEDED': 'bg-pink-500/20 text-pink-400',
        'TTL_EXPIRED': 'bg-pink-600/20 text-pink-300',

        // GTP processing - Blue/Cyan tones
        'ENCAP_FAILED': 'bg-blue-500/20 text-blue-400',
        'DECAP_FAILED': 'bg-blue-600/20 text-blue-300',
        'MALFORMED_GTP': 'bg-cyan-500/20 text-cyan-400',

        // Routing/Kernel - Gray/Slate tones
        'ROUTING_DROP': 'bg-slate-500/20 text-slate-400',
        'KERNEL_DROP': 'bg-slate-600/20 text-slate-300',
    }
    return colors[reason] || 'bg-slate-500/20 text-slate-400'
}

// Format packet length
function formatPktLen(len: number): string {
    if (len >= 1024) return `${(len / 1024).toFixed(1)} KB`
    return `${len} B`
}

export default function DropAlertPanel({ drops }: DropAlertPanelProps) {
    const [selectedDropIndex, setSelectedDropIndex] = useState<number | null>(null)
    const [showAll, setShowAll] = useState(false)
    const hasDrops = drops.total > 0

    // Calculate max count for progress bar
    const maxReasonCount = Math.max(...Object.values(drops.by_reason || {}), 1)

    const displayDrops = showAll
        ? (drops.recent_drops || [])
        : (drops.recent_drops || []).slice(0, 5)

    return (
        <div className="space-y-4">
            {/* Summary */}
            <div className={`p-4 rounded-lg ${hasDrops ? 'bg-red-500/10' : 'bg-green-500/10'}`}>
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <span className={`text-2xl ${hasDrops ? 'pulse-alert' : ''}`}>
                            {hasDrops ? '⚠️' : '✅'}
                        </span>
                        <div>
                            <div className={`font-semibold ${hasDrops ? 'text-red-400' : 'text-green-400'}`}>
                                {hasDrops ? `${drops.total.toLocaleString()} Drops Detected` : 'No Drops Detected'}
                            </div>
                            <div className="text-sm text-slate-400">
                                Drop Rate: {drops.rate_percent.toFixed(4)}%
                            </div>
                        </div>
                    </div>
                    {hasDrops && (
                        <div className="text-right">
                            <div className="text-2xl font-bold text-red-400">
                                {drops.rate_percent.toFixed(2)}%
                            </div>
                            <div className="text-xs text-slate-500">packet loss</div>
                        </div>
                    )}
                </div>
            </div>

            {/* Drop Reasons Breakdown with Progress Bars */}
            {Object.keys(drops.by_reason || {}).length > 0 && (
                <div>
                    <h3 className="text-sm font-medium text-slate-300 mb-3">Drop Reasons Breakdown</h3>
                    <div className="space-y-3">
                        {Object.entries(drops.by_reason)
                            .sort(([, a], [, b]) => b - a)
                            .map(([reason, count]) => (
                                <div key={reason}>
                                    <div className="flex items-center justify-between mb-1">
                                        <span className={`text-xs px-2 py-0.5 rounded ${getReasonColor(reason)}`}>
                                            {reason}
                                        </span>
                                        <span className="text-sm font-mono text-slate-300">
                                            {count.toLocaleString()} ({((count / drops.total) * 100).toFixed(1)}%)
                                        </span>
                                    </div>
                                    <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gradient-to-r from-red-500 to-red-400 transition-all duration-500"
                                            style={{ width: `${(count / maxReasonCount) * 100}%` }}
                                        />
                                    </div>
                                </div>
                            ))}
                    </div>
                </div>
            )}

            {/* Recent Drops Table - Enhanced */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-medium text-slate-300">Recent Drop Events</h3>
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
                    <div className="text-center py-6 text-slate-500 text-sm bg-slate-800/30 rounded-lg">
                        <div className="text-3xl mb-2">🎉</div>
                        <p>No recent drop events</p>
                        <p className="text-xs mt-1">Network is running smoothly</p>
                    </div>
                ) : (
                    <div className="space-y-2 max-h-80 overflow-y-auto">
                        {displayDrops.map((drop, idx) => (
                            <div
                                key={idx}
                                className={`p-3 rounded-lg border cursor-pointer transition-all ${selectedDropIndex === idx
                                    ? 'bg-slate-700/50 border-cyan-500'
                                    : 'bg-slate-800/30 border-slate-700 hover:border-slate-600'
                                    }`}
                                onClick={() => setSelectedDropIndex(selectedDropIndex === idx ? null : idx)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <span className={`text-lg ${drop.direction === 'uplink' ? 'text-green-400' : 'text-blue-400'}`}>
                                            {drop.direction === 'uplink' ? '↑' : '↓'}
                                        </span>
                                        <div>
                                            <div className="flex items-center gap-2">
                                                <span className="font-mono text-cyan-400 text-sm">{drop.teid}</span>
                                                <span className={`text-xs px-2 py-0.5 rounded ${getReasonColor(drop.reason)}`}>
                                                    {drop.reason}
                                                </span>
                                            </div>
                                            <div className="text-xs text-slate-500 mt-0.5">
                                                {new Date(drop.timestamp).toLocaleString()}
                                            </div>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-sm font-mono text-slate-300">
                                            {formatPktLen(drop.pkt_len)}
                                        </div>
                                    </div>
                                </div>

                                {/* Expanded Details */}
                                {selectedDropIndex === idx && (
                                    <div className="mt-3 pt-3 border-t border-slate-700 grid grid-cols-2 gap-3 text-xs">
                                        <div>
                                            <span className="text-slate-500">Source IP:</span>
                                            <span className="ml-2 font-mono text-slate-300">{drop.src_ip}</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500">Dest IP:</span>
                                            <span className="ml-2 font-mono text-slate-300">{drop.dst_ip}</span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500">Direction:</span>
                                            <span className={`ml-2 ${drop.direction === 'uplink' ? 'text-green-400' : 'text-blue-400'}`}>
                                                {drop.direction === 'uplink' ? 'Uplink (UE → DN)' : 'Downlink (DN → UE)'}
                                            </span>
                                        </div>
                                        <div>
                                            <span className="text-slate-500">Packet Size:</span>
                                            <span className="ml-2 font-mono text-slate-300">{drop.pkt_len} bytes</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}
