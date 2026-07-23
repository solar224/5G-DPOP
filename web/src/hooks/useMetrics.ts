import { useState, useEffect, useCallback, useRef } from 'react'
import {
    TrafficStats,
    DropStats,
    SessionInfo,
    fetchTrafficMetrics,
    fetchDropMetrics,
    fetchSessions,
    createMetricsWebSocket
} from '../services/api'
import { formatEnglishTime } from '../utils/dateTime'

interface MetricsState {
    metrics: TrafficStats
    drops: DropStats
    sessions: SessionInfo[]
    connected: boolean
    error: string | null
}

const defaultMetrics: TrafficStats = {
    uplink: { packets: 0, bytes: 0, packets_per_second: 0, throughput_mbps: 0, last_updated: '' },
    downlink: { packets: 0, bytes: 0, packets_per_second: 0, throughput_mbps: 0, last_updated: '' },
}

const defaultDrops: DropStats = {
    total: 0,
    user_plane_total: 0,
    infrastructure_total: 0,
    uncorrelated_total: 0,
    rate_percent: 0,
    rate_basis: 'user-plane drop events / valid gtp5g user-plane attempts',
    recent_drops: [],
    by_reason: {},
}

function normalizeTraffic(value: TrafficStats | null | undefined): TrafficStats {
    return {
        uplink: {
            packets: value?.uplink?.packets ?? 0,
            bytes: value?.uplink?.bytes ?? 0,
            packets_per_second: value?.uplink?.packets_per_second ?? 0,
            throughput_mbps: value?.uplink?.throughput_mbps ?? 0,
            last_updated: value?.uplink?.last_updated ?? '',
        },
        downlink: {
            packets: value?.downlink?.packets ?? 0,
            bytes: value?.downlink?.bytes ?? 0,
            packets_per_second: value?.downlink?.packets_per_second ?? 0,
            throughput_mbps: value?.downlink?.throughput_mbps ?? 0,
            last_updated: value?.downlink?.last_updated ?? '',
        },
    }
}

function normalizeDrops(value: DropStats | null | undefined): DropStats {
    return {
        total: value?.total ?? 0,
        user_plane_total: value?.user_plane_total ?? 0,
        infrastructure_total: value?.infrastructure_total ?? 0,
        uncorrelated_total: value?.uncorrelated_total ?? 0,
        rate_percent: value?.rate_percent ?? 0,
        rate_basis: value?.rate_basis ?? defaultDrops.rate_basis,
        recent_drops: value?.recent_drops || [],
        by_reason: value?.by_reason || {},
    }
}

export function useMetrics(): MetricsState {
    const [metrics, setMetrics] = useState<TrafficStats>(defaultMetrics)
    const [drops, setDrops] = useState<DropStats>(defaultDrops)
    const [sessions, setSessions] = useState<SessionInfo[]>([])
    const [connected, setConnected] = useState(false)
    const [error, setError] = useState<string | null>(null)

    const wsRef = useRef<WebSocket | null>(null)
    const reconnectTimeoutRef = useRef<number | null>(null)

    const connectWebSocket = useCallback(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) return

        try {
            wsRef.current = createMetricsWebSocket(
                (data) => {
                    setConnected(true)
                    setError(null)

                    if (data.data) {
                        if (data.data.traffic) {
                            setMetrics(normalizeTraffic(data.data.traffic))
                        }
                        if (data.data.drops) {
                            setDrops(normalizeDrops(data.data.drops))
                        }
                    }
                },
                (err) => {
                    console.error('WebSocket error:', err)
                    setError('WebSocket connection error')
                    setConnected(false)
                },
                () => {
                    setConnected(false)
                    reconnectTimeoutRef.current = window.setTimeout(() => {
                        connectWebSocket()
                    }, 3000)
                }
            )
        } catch (e) {
            setError('Failed to create WebSocket connection')
            pollMetrics()
        }
    }, [])

    const pollMetrics = useCallback(async () => {
        try {
            const [trafficData, dropsData, sessionsData] = await Promise.all([
                fetchTrafficMetrics(),
                fetchDropMetrics(),
                fetchSessions(),
            ])

            setMetrics(normalizeTraffic(trafficData))
            setDrops(normalizeDrops(dropsData))
            // Combine all session types so they don't disappear when becoming stale
            const allSessions = [
                ...(sessionsData.sessions || []).map(session => ({ ...session, monitoring_state: 'active' as const })),
                ...(sessionsData.stale_sessions || []).map(session => ({ ...session, monitoring_state: 'stale' as const })),
                ...(sessionsData.pending_sessions || []).map(session => ({ ...session, monitoring_state: 'pending' as const })),
                ...(sessionsData.failed_sessions || []).map(session => ({ ...session, monitoring_state: 'failed' as const })),
                ...(sessionsData.unclassified_sessions || []),
            ]
            setSessions(allSessions)
            setError(null)
        } catch (e) {
            setError('Failed to fetch metrics')
        }
    }, [])

    useEffect(() => {
        pollMetrics()
        connectWebSocket()

        const pollInterval = setInterval(pollMetrics, 2000)

        return () => {
            clearInterval(pollInterval)
            if (reconnectTimeoutRef.current) {
                clearTimeout(reconnectTimeoutRef.current)
            }
            if (wsRef.current) {
                wsRef.current.close()
            }
        }
    }, [connectWebSocket, pollMetrics])

    return { metrics, drops, sessions, connected, error }
}

export function useMetricsHistory(metrics: TrafficStats, maxPoints = 60) {
    const [history, setHistory] = useState<Array<{
        time: string
        uplink: number
        downlink: number
    }>>([])

    useEffect(() => {
        const now = formatEnglishTime(new Date())
        setHistory(prev => {
            const newHistory = [
                ...prev,
                {
                    time: now,
                    uplink: metrics.uplink.throughput_mbps,
                    downlink: metrics.downlink.throughput_mbps,
                }
            ]
            if (newHistory.length > maxPoints) {
                return newHistory.slice(-maxPoints)
            }
            return newHistory
        })
    }, [metrics, maxPoints])

    return history
}
