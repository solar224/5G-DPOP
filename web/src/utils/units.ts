export interface ScaledUnit {
    divisor: number
    unit: string
}

const BYTE_UNITS = ['B', 'kB', 'MB', 'GB', 'TB', 'PB']

export function formatBytes(bytes: number, fractionDigits = 2): string {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
    const index = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1000)),
        BYTE_UNITS.length - 1
    )
    const value = bytes / Math.pow(1000, index)
    return `${value.toFixed(index === 0 ? 0 : fractionDigits)} ${BYTE_UNITS[index]}`
}

export function selectBitRateUnit(bitsPerSecond: number): ScaledUnit {
    const absolute = Math.abs(bitsPerSecond)
    if (absolute >= 1_000_000_000) return { divisor: 1_000_000_000, unit: 'Gbps' }
    if (absolute >= 1_000_000) return { divisor: 1_000_000, unit: 'Mbps' }
    if (absolute >= 1_000) return { divisor: 1_000, unit: 'kbps' }
    return { divisor: 1, unit: 'bps' }
}

export function formatBitRate(bitsPerSecond: number, fractionDigits = 2): string {
    if (!Number.isFinite(bitsPerSecond) || bitsPerSecond <= 0) return '0 bps'
    const scale = selectBitRateUnit(bitsPerSecond)
    const value = bitsPerSecond / scale.divisor
    return `${value.toFixed(scale.unit === 'bps' ? 0 : fractionDigits)} ${scale.unit}`
}

export function formatMbps(megabitsPerSecond: number): string {
    return formatBitRate(megabitsPerSecond * 1_000_000)
}

export function formatByteRate(bytesPerSecond: number): string {
    return formatBitRate(bytesPerSecond * 8)
}

export function formatPacketRate(packetsPerSecond: number): string {
    if (!Number.isFinite(packetsPerSecond) || packetsPerSecond <= 0) return '0 pps'
    if (packetsPerSecond >= 1000) return `${(packetsPerSecond / 1000).toFixed(2)} kpps`
    return `${packetsPerSecond.toFixed(packetsPerSecond < 10 ? 2 : 1)} pps`
}

export function formatKbps(kilobitsPerSecond: number): string {
    return formatBitRate(kilobitsPerSecond * 1000)
}
