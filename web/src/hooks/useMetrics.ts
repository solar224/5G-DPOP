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

interface MetricsState {
    metrics: TrafficStats
    drops: DropStats
    sessions: SessionInfo[]
    connected: boolean
    error: string | null
}

const defaultMetrics: TrafficStats = {
    uplink: { packets: 0, bytes: 0, throughput_mbps: 0, last_updated: '' },
    downlink: { packets: 0, bytes: 0, throughput_mbps: 0, last_updated: '' },
}

const defaultDrops: DropStats = {
    total: 0,
    rate_percent: 0,
    recent_drops: [],
    by_reason: {},
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
                            setMetrics(data.data.traffic)
                        }
                        if (data.data.drops) {
                            setDrops(data.data.drops)
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

            setMetrics(trafficData)
            setDrops({
                ...dropsData,
                recent_drops: dropsData.recent_drops || [],
                by_reason: dropsData.by_reason || {},
            })
            // Combine all session types so they don't disappear when becoming stale
            const allSessions = [
                ...(sessionsData.sessions || []),
                ...(sessionsData.stale_sessions || []),
                ...(sessionsData.pending_sessions || []),
                ...(sessionsData.failed_sessions || []),
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
        const now = new Date().toLocaleTimeString()
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
