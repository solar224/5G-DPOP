import { useState, useEffect, useRef, useMemo } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { TrafficStats } from '../services/api'

interface TrafficChartProps {
    metrics: TrafficStats
}

interface DataPoint {
    time: string
    timestamp: number
    uplink: number
    downlink: number
}

export default function TrafficChart({ metrics }: TrafficChartProps) {
    const [history, setHistory] = useState<DataPoint[]>([])
    const lastUpdateRef = useRef<number>(0)
    // Auto-detect unit: if max throughput > 0.1 Mbps, use Mbps; otherwise use Kbps
    const [useKbps, setUseKbps] = useState(true)

    useEffect(() => {
        const now = Date.now()

        // Throttle updates to prevent too frequent re-renders (minimum 900ms between updates)
        if (now - lastUpdateRef.current < 900) {
            return
        }
        lastUpdateRef.current = now

        const timeStr = new Date().toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        })

        // Get raw Mbps values
        const rawUplink = metrics.uplink.throughput_mbps
        const rawDownlink = metrics.downlink.throughput_mbps

        // Auto-detect if we should use Kbps or Mbps
        // If any value exceeds 0.1 Mbps (100 Kbps), switch to Mbps
        const maxRaw = Math.max(rawUplink, rawDownlink)
        if (maxRaw > 0.1) {
            setUseKbps(false)
        } else if (maxRaw < 0.01 && history.every(h => h.uplink < 100 && h.downlink < 100)) {
            setUseKbps(true)
        }

        setHistory(prev => {
            // Store values in the current unit for display
            // If useKbps, multiply by 1000 to convert Mbps to Kbps
            const multiplier = useKbps ? 1000 : 1

            // Keep more decimal precision for small values
            const uplinkValue = rawUplink * multiplier
            const downlinkValue = rawDownlink * multiplier

            const newPoint: DataPoint = {
                time: timeStr,
                timestamp: now,
                uplink: Math.round(uplinkValue * 10000) / 10000,
                downlink: Math.round(downlinkValue * 10000) / 10000,
            }

            // Debug log to help troubleshoot
            if (rawUplink > 0 || rawDownlink > 0) {
                console.log(`TrafficChart: raw=${rawUplink.toFixed(6)}/${rawDownlink.toFixed(6)} Mbps, display=${newPoint.uplink}/${newPoint.downlink} ${useKbps ? 'Kbps' : 'Mbps'}`)
            }

            const newHistory = [...prev, newPoint]

            // Keep only last 60 entries (1 minute of data at 1s interval)
            if (newHistory.length > 60) {
                return newHistory.slice(-60)
            }
            return newHistory
        })
    }, [metrics, useKbps])

    // Calculate stable Y-axis domain based on data
    const yAxisDomain = useMemo(() => {
        if (history.length === 0) return [0, 1]

        const allValues = history.flatMap(d => [d.uplink, d.downlink])
        const maxValue = Math.max(...allValues, 0.001)

        // Round up to nice intervals to prevent axis jumping
        let ceiling: number
        if (useKbps) {
            // Kbps scale
            if (maxValue <= 0.1) ceiling = 0.5
            else if (maxValue <= 0.5) ceiling = 1
            else if (maxValue <= 1) ceiling = 2
            else if (maxValue <= 2) ceiling = 5
            else if (maxValue <= 5) ceiling = 10
            else if (maxValue <= 10) ceiling = 20
            else if (maxValue <= 20) ceiling = 50
            else if (maxValue <= 50) ceiling = 100
            else if (maxValue <= 100) ceiling = 200
            else if (maxValue <= 200) ceiling = 500
            else if (maxValue <= 500) ceiling = 1000
            else ceiling = Math.ceil(maxValue / 500) * 500
        } else {
            // Mbps scale
            if (maxValue <= 0.1) ceiling = 0.1
            else if (maxValue <= 0.5) ceiling = 0.5
            else if (maxValue <= 1) ceiling = 1
            else if (maxValue <= 2) ceiling = 2
            else if (maxValue <= 5) ceiling = 5
            else if (maxValue <= 10) ceiling = 10
            else if (maxValue <= 20) ceiling = 20
            else if (maxValue <= 50) ceiling = 50
            else if (maxValue <= 100) ceiling = 100
            else ceiling = Math.ceil(maxValue / 50) * 50
        }

        return [0, ceiling]
    }, [history, useKbps])

    // Format X-axis ticks to show only every 10 seconds
    const formatXAxis = (time: string, index: number) => {
        if (history.length <= 10) return time
        // Show tick every 10 data points
        if (index % 10 === 0 || index === history.length - 1) {
            return time.slice(0, 5) // Show HH:MM only
        }
        return ''
    }

    if (history.length < 2) {
        return (
            <div className="h-64 flex items-center justify-center text-slate-400">
                <div className="text-center">
                    <div className="animate-pulse mb-2">📊</div>
                    <p>Collecting data...</p>
                </div>
            </div>
        )
    }

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <LineChart
                    data={history}
                    margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                >
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis
                        dataKey="time"
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        tickFormatter={formatXAxis}
                        interval={0}
                        tick={{ fill: '#64748b' }}
                    />
                    <YAxis
                        stroke="#64748b"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        domain={yAxisDomain}
                        tickFormatter={(value) => `${value}`}
                        width={50}
                        label={{
                            value: useKbps ? 'Kbps' : 'Mbps',
                            angle: -90,
                            position: 'insideLeft',
                            style: { fill: '#64748b', fontSize: 11 }
                        }}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: '#1e293b',
                            border: '1px solid #334155',
                            borderRadius: '8px',
                        }}
                        labelStyle={{ color: '#e2e8f0' }}
                        formatter={(value: number) => [`${value.toFixed(3)} ${useKbps ? 'Kbps' : 'Mbps'}`]}
                    />
                    <Legend />
                    <Line
                        type="monotone"
                        dataKey="uplink"
                        stroke="#22c55e"
                        strokeWidth={2}
                        dot={false}
                        name="Uplink"
                        isAnimationActive={false}
                    />
                    <Line
                        type="monotone"
                        dataKey="downlink"
                        stroke="#3b82f6"
                        strokeWidth={2}
                        dot={false}
                        name="Downlink"
                        isAnimationActive={false}
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    )
}
