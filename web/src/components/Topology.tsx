import { useEffect, useState } from 'react'
import { Smartphone, Radio, Server, Globe, HelpCircle } from 'lucide-react'
import { SessionInfo, DropStats, fetchTopology, TopologyData, TopologyNode } from '../services/api'

interface TopologyProps {
    sessions: SessionInfo[]
    drops: DropStats
    theme?: 'dark' | 'light'
}

export default function Topology({ sessions, drops, theme = 'dark' }: TopologyProps) {
    const [topology, setTopology] = useState<TopologyData | null>(null)
    const [loading, setLoading] = useState(true)
    const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null)
    const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })

    useEffect(() => {
        const loadTopology = async () => {
            try {
                const data = await fetchTopology()
                setTopology(data)
            } catch (err) {
                console.error('Failed to load topology:', err)
            } finally {
                setLoading(false)
            }
        }

        loadTopology()
        const interval = setInterval(loadTopology, 5000)
        return () => clearInterval(interval)
    }, [])

    const isDark = theme === 'dark'
    const textColor = isDark ? '#e2e8f0' : '#1e293b'
    const subTextColor = isDark ? '#94a3b8' : '#64748b'
    const nodeBg = isDark ? '#1e293b' : '#ffffff'
    const linkColor = isDark ? '#64748b' : '#94a3b8'
    const trafficColor = isDark ? '#4ade80' : '#22c55e'
    const tooltipBg = isDark ? 'bg-slate-800' : 'bg-white'
    const tooltipBorder = isDark ? 'border-slate-700' : 'border-slate-200'
    const tooltipText = isDark ? 'text-slate-200' : 'text-slate-700'

    if (loading && !topology) {
        return <div className="text-center py-10 text-slate-500">Loading topology...</div>
    }

    if (!topology || topology.nodes.length === 0) {
        return <div className="text-center py-10 text-slate-500">No topology data available</div>
    }

    const nodesByType: Record<string, TopologyNode[]> = {
        'ue': [], 'gnb': [], 'upf': [], 'dn': []
    }
    topology.nodes.forEach(n => {
        if (nodesByType[n.type]) nodesByType[n.type].push(n)
    })
    Object.keys(nodesByType).forEach(type => {
        nodesByType[type].sort((a, b) => a.id.localeCompare(b.id))
    })

    const width = 800
    const padding = 30

    const maxNodes = Math.max(...Object.values(nodesByType).map(n => n.length))
    const minHeight = 350
    const height = Math.max(minHeight, maxNodes * 120 + padding * 2)

    const layers = ['ue', 'gnb', 'upf', 'dn']
    const layerX = {
        'ue': width * 0.1,
        'gnb': width * 0.35,
        'upf': width * 0.65,
        'dn': width * 0.9
    }

    const nodePositions: Record<string, { x: number, y: number }> = {}

    Object.entries(nodesByType).forEach(([type, nodes]) => {
        const x = layerX[type as keyof typeof layerX]
        const count = nodes.length
        const step = (height - padding * 2) / (count + 1)

        nodes.forEach((node, idx) => {
            nodePositions[node.id] = {
                x,
                y: padding + step * (idx + 1)
            }
        })
    })

    const getIcon = (type: string, props: any) => {
        switch (type) {
            case 'ue': return <Smartphone {...props} />
            case 'gnb': return <Radio {...props} />
            case 'upf': return <Server {...props} />
            case 'dn': return <Globe {...props} />
            default: return <HelpCircle {...props} />
        }
    }

    const getColor = (type: string) => {
        switch (type) {
            case 'ue': return '#22c55e'
            case 'gnb': return '#06b6d4'
            case 'upf': return '#3b82f6'
            case 'dn': return '#a855f7'
            default: return '#64748b'
        }
    }

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 B'
        const k = 1024
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    const getNodeStats = (node: TopologyNode) => {
        const stats = []

        if (node.type === 'ue') {
            const session = sessions.find(s => s.ue_ip === node.ip || s.ue_ip === node.id)
            if (session) {
                stats.push({ label: 'SUPI', value: session.supi || 'Unknown' })
                stats.push({ label: 'IP', value: session.ue_ip })
                stats.push({ label: 'UL Packets', value: session.packets_ul.toLocaleString() })
                stats.push({ label: 'DL Packets', value: session.packets_dl.toLocaleString() })
                stats.push({ label: 'UL Bytes', value: formatBytes(session.bytes_ul) })
                stats.push({ label: 'DL Bytes', value: formatBytes(session.bytes_dl) })
            } else {
                stats.push({ label: 'Status', value: 'Idle' })
            }
        } else if (node.type === 'upf') {
            const totalPackets = sessions.reduce((acc, s) => acc + s.packets_ul + s.packets_dl, 0)
            const totalBytes = sessions.reduce((acc, s) => acc + s.bytes_ul + s.bytes_dl, 0)
            stats.push({ label: 'Active Sessions', value: sessions.length })
            stats.push({ label: 'Total Drops', value: drops.total, alert: drops.total > 0 })
            stats.push({ label: 'Total Packets', value: totalPackets.toLocaleString() })
            stats.push({ label: 'Total Traffic', value: formatBytes(totalBytes) })
        } else if (node.type === 'gnb') {
            const connectedSessions = sessions.filter(s => s.gnb_ip === node.ip)
            stats.push({ label: 'IP', value: node.ip })
            stats.push({ label: 'Connected UEs', value: connectedSessions.length })
        } else {
            stats.push({ label: 'IP', value: node.ip || 'N/A' })
        }

        return stats
    }

    const handleMouseMove = (e: React.MouseEvent) => {
        setTooltipPos({ x: e.clientX + 15, y: e.clientY + 15 })
    }

    return (
        <div className="w-full overflow-hidden">
            <div className="w-full relative">
                <svg
                    viewBox={`0 0 ${width} ${height}`}
                    className="w-full h-auto"
                    preserveAspectRatio="xMidYMid meet"
                >
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill={linkColor} />
                        </marker>
                    </defs>

                    {topology.links.map((link, idx) => {
                        const start = nodePositions[link.source]
                        const end = nodePositions[link.target]
                        if (!start || !end) return null

                        const hasTraffic = link.hasActiveTraffic === true

                        return (
                            <g key={`${link.source}-${link.target}-${idx}`}>
                                <line
                                    x1={start.x}
                                    y1={start.y}
                                    x2={end.x}
                                    y2={end.y}
                                    stroke={hasTraffic ? trafficColor : linkColor}
                                    strokeWidth={hasTraffic ? "3" : "2"}
                                    markerEnd="url(#arrowhead)"
                                    strokeDasharray={link.type === 'n3' ? "5,5" : ""}
                                    opacity={hasTraffic ? 1 : 0.5}
                                    className="transition-all duration-500"
                                />
                                {hasTraffic && (
                                    <circle r="4" fill={trafficColor}>
                                        <animate
                                            attributeName="cx"
                                            from={start.x}
                                            to={end.x}
                                            dur="1.5s"
                                            repeatCount="indefinite"
                                        />
                                        <animate
                                            attributeName="cy"
                                            from={start.y}
                                            to={end.y}
                                            dur="1.5s"
                                            repeatCount="indefinite"
                                        />
                                        <animate
                                            attributeName="opacity"
                                            values="0;1;1;0"
                                            keyTimes="0;0.1;0.9;1"
                                            dur="1.5s"
                                            repeatCount="indefinite"
                                        />
                                    </circle>
                                )}
                                {hasTraffic && (
                                    <line
                                        x1={start.x}
                                        y1={start.y}
                                        x2={end.x}
                                        y2={end.y}
                                        stroke={trafficColor}
                                        strokeWidth="6"
                                        strokeDasharray={link.type === 'n3' ? "5,5" : ""}
                                        opacity={0.3}
                                        filter="blur(3px)"
                                    />
                                )}
                                <text
                                    x={(start.x + end.x) / 2}
                                    y={(start.y + end.y) / 2 - 8}
                                    textAnchor="middle"
                                    fill={hasTraffic ? trafficColor : subTextColor}
                                    fontSize="11"
                                    fontWeight={hasTraffic ? "bold" : "normal"}
                                >
                                    {link.label || link.type.toUpperCase()}
                                </text>
                                {/* Show traffic rate when active */}
                                {(link.trafficRate ?? 0) > 0 && (
                                    <text
                                        x={(start.x + end.x) / 2}
                                        y={(start.y + end.y) / 2 + 6}
                                        textAnchor="middle"
                                        fill={hasTraffic ? trafficColor : subTextColor}
                                        fontSize="9"
                                        fontFamily="monospace"
                                    >
                                        {/* trafficRate is in bytes/sec, convert to appropriate unit */}
                                        {(link.trafficRate ?? 0) >= 1024 * 1024
                                            ? `${((link.trafficRate ?? 0) / 1024 / 1024).toFixed(1)} MB/s`
                                            : (link.trafficRate ?? 0) >= 1024
                                                ? `${((link.trafficRate ?? 0) / 1024).toFixed(1)} KB/s`
                                                : `${(link.trafficRate ?? 0).toFixed(0)} B/s`}
                                    </text>
                                )}
                            </g>
                        )
                    })}

                    {topology.nodes.map((node) => {
                        const pos = nodePositions[node.id]
                        if (!pos) return null
                        let color = getColor(node.type)

                        const isUpfWithDrops = node.type === 'upf' && drops.total > 0
                        if (isUpfWithDrops) {
                            color = '#ef4444'
                        }

                        return (
                            <g
                                key={node.id}
                                transform={`translate(${pos.x}, ${pos.y})`}
                                onMouseEnter={(e) => {
                                    setHoveredNode(node)
                                    setTooltipPos({ x: e.clientX + 15, y: e.clientY + 15 })
                                }}
                                onMouseMove={handleMouseMove}
                                onMouseLeave={() => setHoveredNode(null)}
                                className="cursor-pointer"
                            >
                                {isUpfWithDrops && (
                                    <circle r="24" fill="none" stroke="#ef4444" strokeWidth="2" opacity="0.5">
                                        <animate attributeName="r" from="24" to="34" dur="1s" repeatCount="indefinite" />
                                        <animate attributeName="opacity" from="0.5" to="0" dur="1s" repeatCount="indefinite" />
                                    </circle>
                                )}

                                <circle
                                    r="24"
                                    fill={nodeBg}
                                    stroke={color}
                                    strokeWidth="2"
                                    className="transition-all duration-300"
                                />

                                <g transform="translate(-12, -12)">
                                    {getIcon(node.type, { size: 24, color: color })}
                                </g>

                                <text
                                    x="0"
                                    y="35"
                                    textAnchor="middle"
                                    fill={textColor}
                                    fontSize="13"
                                    fontWeight="bold"
                                >
                                    {node.label}
                                </text>
                                {/* Show IP only if different from label and type is not DN */}
                                {node.ip && node.type !== 'dn' && (
                                    <text
                                        x="0"
                                        y="48"
                                        textAnchor="middle"
                                        fill={subTextColor}
                                        fontSize="9"
                                        fontFamily="monospace"
                                    >
                                        {node.ip}
                                    </text>
                                )}
                                {/* Data Plane Verification Badge */}
                                {node.verified !== undefined && (
                                    <g transform="translate(18, -18)">
                                        <circle
                                            r="8"
                                            fill={node.verified ? '#22c55e' : '#f59e0b'}
                                            stroke={isDark ? '#1e293b' : '#ffffff'}
                                            strokeWidth="2"
                                        />
                                        <text
                                            x="0"
                                            y="3"
                                            textAnchor="middle"
                                            fill="white"
                                            fontSize="9"
                                            fontWeight="bold"
                                        >
                                            {node.verified ? '✓' : '?'}
                                        </text>
                                    </g>
                                )}
                                {/* Data Plane Status Indicator */}
                                {node.dataPlaneStatus === 'active' && (
                                    <g transform="translate(-18, -18)">
                                        <circle r="6" fill="#22c55e">
                                            <animate attributeName="opacity" values="1;0.5;1" dur="2s" repeatCount="indefinite" />
                                        </circle>
                                    </g>
                                )}
                                {node.dataPlaneStatus === 'stale' && (
                                    <g transform="translate(-18, -18)">
                                        <circle r="6" fill="#f59e0b" />
                                    </g>
                                )}
                                {/* Session Count Badge for UPF */}
                                {node.type === 'upf' && sessions.length > 0 && (
                                    <g transform="translate(20, 15)">
                                        <rect
                                            x="-12"
                                            y="-8"
                                            width="24"
                                            height="16"
                                            rx="4"
                                            fill="#3b82f6"
                                            stroke={isDark ? '#1e293b' : '#ffffff'}
                                            strokeWidth="1"
                                        />
                                        <text
                                            x="0"
                                            y="4"
                                            textAnchor="middle"
                                            fill="white"
                                            fontSize="10"
                                            fontWeight="bold"
                                        >
                                            {sessions.length}
                                        </text>
                                    </g>
                                )}
                                {/* Connected UE Count Badge for gNB */}
                                {node.type === 'gnb' && (
                                    <g transform="translate(20, 15)">
                                        <rect
                                            x="-12"
                                            y="-8"
                                            width="24"
                                            height="16"
                                            rx="4"
                                            fill="#8b5cf6"
                                            stroke={isDark ? '#1e293b' : '#ffffff'}
                                            strokeWidth="1"
                                        />
                                        <text
                                            x="0"
                                            y="4"
                                            textAnchor="middle"
                                            fill="white"
                                            fontSize="10"
                                            fontWeight="bold"
                                        >
                                            {sessions.filter(s => s.gnb_ip === node.ip).length}
                                        </text>
                                    </g>
                                )}
                            </g>
                        )
                    })}
                </svg>

                {hoveredNode && (
                    <div
                        className={`fixed z-50 p-4 rounded-lg shadow-xl border ${tooltipBg} ${tooltipBorder} pointer-events-none`}
                        style={{ left: tooltipPos.x, top: tooltipPos.y }}
                    >
                        <div className={`font-bold mb-2 ${tooltipText} border-b ${isDark ? 'border-slate-700' : 'border-slate-200'} pb-1`}>
                            {hoveredNode.label}
                        </div>
                        <div className="space-y-1">
                            {getNodeStats(hoveredNode).map((stat, idx) => (
                                <div key={idx} className="flex items-center justify-between gap-4 text-sm">
                                    <span className={subTextColor}>{stat.label}:</span>
                                    <span className={`${stat.alert ? 'text-red-500 font-bold' : tooltipText} font-mono`}>
                                        {stat.value}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div className={`absolute bottom-4 right-4 p-3 rounded-lg border text-xs ${isDark ? 'bg-slate-800/80 border-slate-700' : 'bg-white/80 border-gray-200'
                    }`}>
                    <div className={`font-semibold mb-2 ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>Legend</div>
                    <div className="space-y-1">
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-green-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>UE (User Equipment)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-cyan-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>gNB (Base Station)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-blue-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>UPF (User Plane)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-purple-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>DN (Data Network)</span>
                        </div>
                        <div className={`border-t ${isDark ? 'border-slate-700' : 'border-gray-200'} mt-2 pt-2`}>
                            <div className={`font-semibold mb-1 ${isDark ? 'text-slate-400' : 'text-gray-600'}`}>Traffic</div>
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-0.5 bg-green-500 rounded"></span>
                                <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>Active Flow</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className="w-8 h-0.5 bg-slate-500 opacity-50 rounded"></span>
                                <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>Idle Path</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
