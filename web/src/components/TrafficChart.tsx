import { useEffect, useMemo, useRef, useState } from 'react'
import {
    Area,
    CartesianGrid,
    ComposedChart,
    Legend,
    Line,
    LineChart,
    ReferenceLine,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts'
import { TrafficStats } from '../services/api'
import { formatPacketRate, selectBitRateUnit } from '../utils/units'

interface TrafficChartProps {
    metrics: TrafficStats
    theme?: 'dark' | 'light'
}

interface RawDataPoint {
    time: string
    timestamp: number
    uplinkBps: number
    downlinkBps: number
    uplinkPps: number
    downlinkPps: number
    uplinkPackets: number
    downlinkPackets: number
}

interface DisplayDataPoint extends RawDataPoint {
    uplink: number
    downlink: number
}

type ChartMode = 'throughput' | 'packets' | 'combined'

const HISTORY_WINDOW_MS = 60_000

function validTimestamp(value: string): number {
    const parsed = Date.parse(value)
    return Number.isFinite(parsed) ? parsed : 0
}

function niceCeiling(maxValue: number): number {
    if (!Number.isFinite(maxValue) || maxValue <= 0) return 1
    const magnitude = Math.pow(10, Math.floor(Math.log10(maxValue)))
    const normalized = maxValue / magnitude
    const multiplier = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10
    return multiplier * magnitude
}

function average(values: number[]): number {
    if (values.length === 0) return 0
    return values.reduce((sum, value) => sum + value, 0) / values.length
}

function safeWindowDelta(current: number, first: number): number {
    return current >= first ? current - first : 0
}

export default function TrafficChart({ metrics, theme = 'dark' }: TrafficChartProps) {
    const [history, setHistory] = useState<RawDataPoint[]>([])
    const [chartMode, setChartMode] = useState<ChartMode>('throughput')
    const lastSampleKeyRef = useRef('')

    const gridColor = theme === 'dark' ? '#334155' : '#e2e8f0'
    const axisColor = theme === 'dark' ? '#64748b' : '#94a3b8'
    const tooltipBg = theme === 'dark' ? '#1e293b' : '#ffffff'
    const tooltipBorder = theme === 'dark' ? '#334155' : '#e2e8f0'
    const textColor = theme === 'dark' ? '#e2e8f0' : '#1e293b'
    const mutedText = theme === 'dark' ? 'text-slate-400' : 'text-gray-500'
    const statsBg = theme === 'dark' ? 'bg-slate-700/30' : 'bg-gray-100'
    const buttonBg = theme === 'dark' ? 'bg-slate-700' : 'bg-gray-200'
    const buttonText = theme === 'dark' ? 'text-slate-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'

    useEffect(() => {
        const sampleKey = [
            metrics.uplink.last_updated,
            metrics.downlink.last_updated,
            metrics.uplink.packets,
            metrics.downlink.packets,
            metrics.uplink.throughput_mbps,
            metrics.downlink.throughput_mbps,
            metrics.uplink.packets_per_second,
            metrics.downlink.packets_per_second,
        ].join('|')

        // REST polling and WebSocket delivery can carry the same server sample.
        // Record it once so that one second of traffic is not double-counted.
        if (sampleKey === lastSampleKeyRef.current) return
        lastSampleKeyRef.current = sampleKey

        const serverTimestamp = Math.max(
            validTimestamp(metrics.uplink.last_updated),
            validTimestamp(metrics.downlink.last_updated)
        )
        const timestamp = serverTimestamp || Date.now()
        const point: RawDataPoint = {
            timestamp,
            time: new Date(timestamp).toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            }),
            // The API contract is decimal megabits per second.
            uplinkBps: Math.max(0, metrics.uplink.throughput_mbps * 1_000_000),
            downlinkBps: Math.max(0, metrics.downlink.throughput_mbps * 1_000_000),
            uplinkPps: Math.max(0, metrics.uplink.packets_per_second),
            downlinkPps: Math.max(0, metrics.downlink.packets_per_second),
            uplinkPackets: Math.max(0, metrics.uplink.packets),
            downlinkPackets: Math.max(0, metrics.downlink.packets),
        }

        setHistory(previous => {
            const next = [...previous.filter(item => item.timestamp !== timestamp), point]
                .sort((a, b) => a.timestamp - b.timestamp)
            const newestTimestamp = next[next.length - 1]?.timestamp ?? timestamp
            return next.filter(item => item.timestamp >= newestTimestamp - HISTORY_WINDOW_MS)
        })
    }, [metrics])

    const rateScale = useMemo(() => {
        const maximum = Math.max(
            ...history.flatMap(point => [point.uplinkBps, point.downlinkBps]),
            0
        )
        return selectBitRateUnit(maximum)
    }, [history])

    const displayData = useMemo<DisplayDataPoint[]>(() => history.map(point => ({
        ...point,
        uplink: point.uplinkBps / rateScale.divisor,
        downlink: point.downlinkBps / rateScale.divisor,
    })), [history, rateScale])

    const stats = useMemo(() => {
        if (displayData.length === 0) return null
        const first = displayData[0]
        const latest = displayData[displayData.length - 1]
        const uplinkRates = displayData.map(point => point.uplink)
        const downlinkRates = displayData.map(point => point.downlink)
        const uplinkPps = displayData.map(point => point.uplinkPps)
        const downlinkPps = displayData.map(point => point.downlinkPps)

        return {
            uplink: {
                avg: average(uplinkRates),
                max: Math.max(...uplinkRates),
                current: latest.uplink,
            },
            downlink: {
                avg: average(downlinkRates),
                max: Math.max(...downlinkRates),
                current: latest.downlink,
            },
            packets: {
                uplinkCurrent: latest.uplinkPps,
                downlinkCurrent: latest.downlinkPps,
                uplinkAvg: average(uplinkPps),
                downlinkAvg: average(downlinkPps),
                uplinkWindow: safeWindowDelta(latest.uplinkPackets, first.uplinkPackets),
                downlinkWindow: safeWindowDelta(latest.downlinkPackets, first.downlinkPackets),
            },
            windowSeconds: Math.min(
                60,
                Math.max(0, Math.round((latest.timestamp - first.timestamp) / 1000))
            ),
        }
    }, [displayData])

    const yAxisDomain = useMemo(() => {
        const values = chartMode === 'packets'
            ? displayData.flatMap(point => [point.uplinkPps, point.downlinkPps])
            : displayData.flatMap(point => [point.uplink, point.downlink])
        return [0, niceCeiling(Math.max(...values, 0))]
    }, [chartMode, displayData])

    const formatXAxis = (time: string, index: number) => {
        if (displayData.length <= 10 || index % 10 === 0 || index === displayData.length - 1) {
            return time
        }
        return ''
    }

    if (displayData.length < 2) {
        return (
            <div className="h-64 flex items-center justify-center text-slate-400">
                <div className="text-center">
                    <div className="animate-pulse mb-2">📊</div>
                    <p>Collecting data...</p>
                </div>
            </div>
        )
    }

    const unit = chartMode === 'packets' ? 'pps' : rateScale.unit
    const windowLabel = `${stats?.windowSeconds ?? 0}s`

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                    <span className={`text-sm ${mutedText}`}>View:</span>
                    <div className={`flex ${buttonBg} rounded-lg p-1`}>
                        {(['throughput', 'packets', 'combined'] as ChartMode[]).map(mode => (
                            <button
                                key={mode}
                                onClick={() => setChartMode(mode)}
                                className={`px-3 py-1 text-sm rounded-md transition-colors ${chartMode === mode
                                    ? 'bg-blue-500 text-white'
                                    : buttonText
                                    }`}
                            >
                                {mode === 'throughput' ? '📈 Throughput' : mode === 'packets' ? '📦 Packet rate' : '📊 Combined'}
                            </button>
                        ))}
                    </div>
                </div>

                {stats && (
                    <div className="flex gap-4 text-sm">
                        <div className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-green-500 rounded-full" />
                            <span className={mutedText}>UL:</span>
                            <span className="text-green-400 font-mono">
                                {chartMode === 'packets'
                                    ? formatPacketRate(stats.packets.uplinkCurrent)
                                    : `${stats.uplink.current.toFixed(2)} ${rateScale.unit}`}
                            </span>
                            <span className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>
                                (avg: {chartMode === 'packets'
                                    ? formatPacketRate(stats.packets.uplinkAvg)
                                    : `${stats.uplink.avg.toFixed(2)} ${rateScale.unit}`})
                            </span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-blue-500 rounded-full" />
                            <span className={mutedText}>DL:</span>
                            <span className="text-blue-400 font-mono">
                                {chartMode === 'packets'
                                    ? formatPacketRate(stats.packets.downlinkCurrent)
                                    : `${stats.downlink.current.toFixed(2)} ${rateScale.unit}`}
                            </span>
                            <span className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>
                                (avg: {chartMode === 'packets'
                                    ? formatPacketRate(stats.packets.downlinkAvg)
                                    : `${stats.downlink.avg.toFixed(2)} ${rateScale.unit}`})
                            </span>
                        </div>
                    </div>
                )}
            </div>

            <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                    {chartMode === 'combined' ? (
                        <ComposedChart data={displayData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                            <XAxis dataKey="time" stroke={axisColor} fontSize={11} tickLine={false} tickFormatter={formatXAxis} interval={0} />
                            <YAxis
                                yAxisId="left"
                                stroke={axisColor}
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={yAxisDomain}
                                label={{ value: rateScale.unit, angle: -90, position: 'insideLeft', style: { fill: axisColor, fontSize: 11 } }}
                            />
                            <YAxis
                                yAxisId="right"
                                orientation="right"
                                stroke={axisColor}
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                label={{ value: 'pps', angle: 90, position: 'insideRight', style: { fill: axisColor, fontSize: 11 } }}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: tooltipBg, border: `1px solid ${tooltipBorder}`, borderRadius: '8px' }}
                                labelStyle={{ color: textColor }}
                            />
                            <Legend />
                            <Area yAxisId="left" type="monotone" dataKey="uplink" fill="#22c55e" fillOpacity={0.2} stroke="#22c55e" strokeWidth={2} name={`↑ UL (${rateScale.unit})`} />
                            <Area yAxisId="left" type="monotone" dataKey="downlink" fill="#3b82f6" fillOpacity={0.2} stroke="#3b82f6" strokeWidth={2} name={`↓ DL (${rateScale.unit})`} />
                            <Line yAxisId="right" type="monotone" dataKey="uplinkPps" stroke="#86efac" strokeWidth={1} strokeDasharray="5 5" dot={false} name="↑ UL pps" />
                            <Line yAxisId="right" type="monotone" dataKey="downlinkPps" stroke="#93c5fd" strokeWidth={1} strokeDasharray="5 5" dot={false} name="↓ DL pps" />
                        </ComposedChart>
                    ) : (
                        <LineChart data={displayData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
                            <XAxis
                                dataKey="time"
                                stroke={axisColor}
                                fontSize={11}
                                tickLine={false}
                                tickFormatter={formatXAxis}
                                interval={0}
                                tick={{ fill: axisColor }}
                            />
                            <YAxis
                                stroke={axisColor}
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={yAxisDomain}
                                width={54}
                                label={{ value: unit, angle: -90, position: 'insideLeft', style: { fill: axisColor, fontSize: 11 } }}
                            />
                            {stats && chartMode === 'throughput' && (
                                <>
                                    <ReferenceLine y={stats.uplink.avg} stroke="#22c55e" strokeDasharray="3 3" strokeOpacity={0.5} />
                                    <ReferenceLine y={stats.downlink.avg} stroke="#3b82f6" strokeDasharray="3 3" strokeOpacity={0.5} />
                                </>
                            )}
                            <Tooltip
                                contentStyle={{ backgroundColor: tooltipBg, border: `1px solid ${tooltipBorder}`, borderRadius: '8px' }}
                                labelStyle={{ color: textColor }}
                                formatter={(value: number, name: string) => [
                                    chartMode === 'packets' ? formatPacketRate(value) : `${value.toFixed(3)} ${rateScale.unit}`,
                                    name,
                                ]}
                            />
                            <Legend />
                            <Line
                                type="monotone"
                                dataKey={chartMode === 'packets' ? 'uplinkPps' : 'uplink'}
                                stroke="#22c55e"
                                strokeWidth={2}
                                dot={false}
                                name="↑ Uplink"
                                isAnimationActive={false}
                            />
                            <Line
                                type="monotone"
                                dataKey={chartMode === 'packets' ? 'downlinkPps' : 'downlink'}
                                stroke="#3b82f6"
                                strokeWidth={2}
                                dot={false}
                                name="↓ Downlink"
                                isAnimationActive={false}
                            />
                        </LineChart>
                    )}
                </ResponsiveContainer>
            </div>

            {stats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    <div className={`${statsBg} rounded-lg p-2`}>
                        <div className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>Peak Uplink</div>
                        <div className="text-green-400 font-mono">{stats.uplink.max.toFixed(2)} {rateScale.unit}</div>
                    </div>
                    <div className={`${statsBg} rounded-lg p-2`}>
                        <div className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>Peak Downlink</div>
                        <div className="text-blue-400 font-mono">{stats.downlink.max.toFixed(2)} {rateScale.unit}</div>
                    </div>
                    <div className={`${statsBg} rounded-lg p-2`}>
                        <div className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>UL Packets (last {windowLabel})</div>
                        <div className="text-green-400/80 font-mono">{stats.packets.uplinkWindow.toLocaleString('en-US')}</div>
                    </div>
                    <div className={`${statsBg} rounded-lg p-2`}>
                        <div className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-400'}`}>DL Packets (last {windowLabel})</div>
                        <div className="text-blue-400/80 font-mono">{stats.packets.downlinkWindow.toLocaleString('en-US')}</div>
                    </div>
                </div>
            )}
        </div>
    )
}
