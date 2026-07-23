import { useEffect, useMemo, useState } from 'react'
import { FlowRule, SessionInfo, fetchSessions } from '../services/api'
import { formatEnglishDateTime } from '../utils/dateTime'
import { formatBytes, formatKbps } from '../utils/units'

type Theme = 'dark' | 'light'
type SortField = 'created_at' | 'observation_id' | 'ue_ip' | 'packets'

const PFCP_INTERFACES: Record<number, string> = {
    0: 'Access',
    1: 'Core',
    2: 'SGi-LAN / N6-LAN',
    3: 'CP function',
    4: '5G VN internal',
}

const THREE_GPP_INTERFACES: Record<number, string> = {
    0: 'S1-U',
    1: 'S5/S8-U',
    2: 'S4-U',
    3: 'S11-U',
    4: 'S12-U',
    5: 'Gn/Gp-U',
    6: 'S2a-U',
    7: 'S2b-U',
    8: 'eNB downlink',
    9: 'eNB uplink',
    10: 'SGW/UPF downlink',
    11: 'N3 (3GPP access)',
    12: 'N3 (trusted non-3GPP access)',
    13: 'N3 (untrusted non-3GPP access)',
    14: 'N3 (data forwarding)',
    15: 'N9',
    16: 'SGi',
    17: 'N6',
    18: 'N19',
    19: 'S8-U',
    20: 'Gp-U',
}

const PATH_LABELS: Record<string, string> = {
    n3: 'N3',
    n9: 'N9',
    n6: 'N6',
    'access-tunnel': 'Access-side tunnel',
    tunnel: 'GTP-U tunnel',
    local: 'Local forwarding',
}

function timestamp(value: string): string {
    return formatEnglishDateTime(value)
}

function interfaceName(value: number, names: Record<number, string>): string | undefined {
    return value >= 0 ? names[value] || `Interface ${value}` : undefined
}

function endpoint(ip?: string, teid?: string): string | undefined {
    const parts = [ip, teid ? `TEID ${teid}` : undefined].filter(Boolean)
    return parts.length > 0 ? parts.join(' · ') : undefined
}

function sessionStateLabel(session: SessionInfo): string {
    if (session.monitoring_state) {
        return session.monitoring_state.charAt(0).toUpperCase() + session.monitoring_state.slice(1)
    }
    return session.data_plane_status || session.establishment_status || session.status || ''
}

function sessionStateClass(session: SessionInfo): string {
    switch (session.monitoring_state || session.data_plane_status?.toLowerCase()) {
        case 'active':
            return 'bg-green-500/15 text-green-400 border-green-500/30'
        case 'stale':
            return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
        case 'pending':
        case 'inactive':
            return 'bg-blue-500/15 text-blue-400 border-blue-500/30'
        case 'failed':
            return 'bg-red-500/15 text-red-400 border-red-500/30'
        default:
            return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
    }
}

function sessionSearchText(session: SessionInfo): string {
    const rules = session.flow_rules || []
    return [
        session.observation_id,
        session.cp_seid,
        session.up_seid,
        session.ue_ip,
        session.upf_ip,
        session.upf_n3_ip,
        session.gnb_ip,
        session.access_peer_ip,
        session.n9_peer_ip,
        session.dnn,
        session.supi,
        ...(session.local_f_teids || []),
        ...rules.flatMap(rule => [
            rule.local_f_teid,
            rule.local_f_teid_ip,
            rule.outer_teid,
            rule.outer_dst,
            rule.destination_selector,
            rule.network_instance,
        ]),
    ].filter(Boolean).join(' ').toLowerCase()
}

function evidenceSource(session: SessionInfo): string {
    switch (session.source) {
        case 'pfcp':
            return 'Live PFCP capture'
        case 'demo':
            return 'Synthetic demo record'
        case 'manual':
            return 'Manually supplied record'
        case 'log':
            return 'Parsed log record'
        default:
            return session.source || ''
    }
}

interface FactProps {
    label: string
    value: string | number
    mono?: boolean
    theme: Theme
}

function Fact({ label, value, mono = false, theme }: FactProps) {
    return (
        <div className={`rounded-lg border p-3 ${theme === 'dark'
            ? 'bg-slate-900/40 border-slate-700'
            : 'bg-slate-50 border-slate-200'
            }`}>
            <div className={`text-xs mb-1 ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>
                {label}
            </div>
            <div className={`${mono ? 'font-mono' : ''} break-all ${theme === 'dark' ? 'text-slate-100' : 'text-slate-900'}`}>
                {value}
            </div>
        </div>
    )
}

interface TunnelRuleProps {
    rule: FlowRule
    theme: Theme
}

function TunnelRuleRow({ rule, theme }: TunnelRuleProps) {
    const source = interfaceName(rule.source_interface, PFCP_INTERFACES)
    const source3gpp = interfaceName(rule.source_interface_type, THREE_GPP_INTERFACES)
    const destination = interfaceName(rule.destination_interface, PFCP_INTERFACES)
    const destination3gpp = interfaceName(rule.interface_type, THREE_GPP_INTERFACES)
    const localEndpoint = endpoint(rule.local_f_teid_ip, rule.local_f_teid)
    const remoteEndpoint = endpoint(rule.outer_dst, rule.outer_teid)
    const ingressFacts = [source, source3gpp, localEndpoint].filter(Boolean)
    const egressFacts = [destination, destination3gpp, remoteEndpoint].filter(Boolean)
    const selectors = [
        rule.destination_selector && `Destination ${rule.destination_selector}`,
        rule.network_instance && `Network instance ${rule.network_instance}`,
        rule.sdf && `SDF ${rule.sdf}`,
        rule.sdf_observed === false ? 'No SDF filter in the observed PDR' : undefined,
    ].filter(Boolean)

    return (
        <tr className={`border-b align-top ${theme === 'dark' ? 'border-slate-700/70' : 'border-slate-200'}`}>
            <td className="px-3 py-3 font-mono text-cyan-400">PDR {rule.pdr_id}</td>
            <td className="px-3 py-3">
                <div className="space-y-1">
                    {ingressFacts.map(value => (
                        <div key={value} className={value === localEndpoint ? 'font-mono text-green-400' : ''}>
                            {value}
                        </div>
                    ))}
                </div>
            </td>
            <td className="px-3 py-3 font-mono text-purple-400">FAR {rule.far_id}</td>
            <td className="px-3 py-3">
                <div className="space-y-1">
                    {egressFacts.map(value => (
                        <div key={value} className={value === remoteEndpoint ? 'font-mono text-blue-400' : ''}>
                            {value}
                        </div>
                    ))}
                </div>
            </td>
            <td className="px-3 py-3">
                <div className="space-y-1">
                    {rule.path_type && (
                        <div className="text-amber-400">{PATH_LABELS[rule.path_type] || rule.path_type}</div>
                    )}
                    {selectors.map(value => <div key={value}>{value}</div>)}
                </div>
            </td>
        </tr>
    )
}

interface SessionDetailProps {
    session: SessionInfo
    onClose: () => void
    theme: Theme
}

function SessionDetail({ session, onClose, theme }: SessionDetailProps) {
    const textPrimary = theme === 'dark' ? 'text-white' : 'text-slate-900'
    const textSecondary = theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
    const panel = theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-white border-slate-200'
    const section = theme === 'dark' ? 'bg-slate-900/30 border-slate-700' : 'bg-slate-50 border-slate-200'
    const rules = [...(session.flow_rules || [])].sort((a, b) =>
        a.pdr_id - b.pdr_id || a.far_id - b.far_id
    )
    const hasTraffic = session.packets_ul > 0 || session.packets_dl > 0 ||
        session.bytes_ul > 0 || session.bytes_dl > 0
    const hasQoS = Boolean(
        session.gbr_ul_kbps || session.gbr_dl_kbps ||
        session.mbr_ul_kbps || session.mbr_dl_kbps
    )
    const source = evidenceSource(session)
    const synthetic = session.source && session.source !== 'pfcp'

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
            <div className={`max-h-[92vh] w-full max-w-6xl overflow-y-auto rounded-xl border shadow-2xl ${panel}`}>
                <div className="sticky top-0 z-10 flex items-start justify-between bg-gradient-to-r from-cyan-700 to-blue-700 px-6 py-4">
                    <div>
                        <h2 className="text-xl font-bold text-white">
                            {session.ue_ip ? `PDU Session · ${session.ue_ip}` : 'Observed PDU Session'}
                        </h2>
                        <p className="mt-1 font-mono text-sm text-cyan-100">
                            Observation ID {session.observation_id}
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={onClose}
                        className="rounded-lg px-3 py-1 text-xl text-white hover:bg-white/15"
                        aria-label="Close session details"
                    >
                        ×
                    </button>
                </div>

                <div className="space-y-5 p-6">
                    {source && (
                        <div className={`rounded-lg border px-4 py-3 text-sm ${synthetic
                            ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                            : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
                            }`}>
                            Evidence source: {source}
                        </div>
                    )}

                    <section className={`rounded-xl border p-4 ${section}`}>
                        <h3 className={`mb-3 font-semibold ${textPrimary}`}>PFCP identity</h3>
                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                            <Fact label="5G-DPOP observation ID" value={session.observation_id} mono theme={theme} />
                            {session.cp_seid && <Fact label="CP F-SEID (SMF selected)" value={session.cp_seid} mono theme={theme} />}
                            {session.up_seid && <Fact label="UP F-SEID (UPF selected)" value={session.up_seid} mono theme={theme} />}
                            {session.upf_ip && <Fact label="Observed PFCP UPF endpoint" value={session.upf_ip} mono theme={theme} />}
                            {Boolean(session.local_f_teids?.length) && (
                                <Fact
                                    label="Observed local F-TEIDs"
                                    value={(session.local_f_teids as string[]).join(', ')}
                                    mono
                                    theme={theme}
                                />
                            )}
                            {session.establishment_status && (
                                <Fact label="PFCP establishment" value={session.establishment_status} theme={theme} />
                            )}
                        </div>
                    </section>

                    {(session.ue_ip || session.dnn || session.s_nssai || session.session_type ||
                        session.qfi || session.pdu_session_id || session.supi) && (
                        <section className={`rounded-xl border p-4 ${section}`}>
                            <h3 className={`mb-3 font-semibold ${textPrimary}`}>Observed session attributes</h3>
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                                {session.ue_ip && <Fact label="UE IP" value={session.ue_ip} mono theme={theme} />}
                                {session.dnn && <Fact label="DNN / network instance" value={session.dnn} theme={theme} />}
                                {session.s_nssai && <Fact label="S-NSSAI" value={session.s_nssai} mono theme={theme} />}
                                {session.session_type && <Fact label="PFCP PDN type" value={session.session_type} theme={theme} />}
                                {Boolean(session.qfi) && <Fact label="QFI" value={session.qfi as number} theme={theme} />}
                                {Boolean(session.pdu_session_id) && (
                                    <Fact label="PDU session ID" value={session.pdu_session_id as number} theme={theme} />
                                )}
                                {session.supi && <Fact label="SUPI" value={session.supi} mono theme={theme} />}
                            </div>
                        </section>
                    )}

                    {(session.upf_n3_ip || session.gnb_ip || session.access_peer_ip ||
                        session.uplink_peer_ip || session.n9_peer_ip) && (
                        <section className={`rounded-xl border p-4 ${section}`}>
                            <h3 className={`mb-3 font-semibold ${textPrimary}`}>Observed user-plane peers</h3>
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                                {session.upf_n3_ip && <Fact label="Local UPF GTP-U endpoint" value={session.upf_n3_ip} mono theme={theme} />}
                                {session.gnb_ip && <Fact label="gNB endpoint" value={session.gnb_ip} mono theme={theme} />}
                                {session.access_peer_ip && <Fact label="Access-side peer" value={session.access_peer_ip} mono theme={theme} />}
                                {session.uplink_peer_ip && <Fact label="Observed GTP-U ingress peer" value={session.uplink_peer_ip} mono theme={theme} />}
                                {session.n9_peer_ip && <Fact label="N9 peer" value={session.n9_peer_ip} mono theme={theme} />}
                                {session.n9_evidence && <Fact label="N9 classification evidence" value={session.n9_evidence} theme={theme} />}
                            </div>
                        </section>
                    )}

                    {rules.length > 0 && (
                        <section className={`overflow-hidden rounded-xl border ${section}`}>
                            <div className="px-4 pt-4">
                                <h3 className={`font-semibold ${textPrimary}`}>PFCP PDR → FAR forwarding evidence</h3>
                                <p className={`mt-1 text-sm ${textSecondary}`}>
                                    Local F-TEID is the UPF receive endpoint from a PDR. Remote TEID is the FAR Outer Header Creation destination.
                                </p>
                            </div>
                            <div className="mt-3 overflow-x-auto">
                                <table className={`w-full min-w-[900px] text-left text-sm ${textSecondary}`}>
                                    <thead className={theme === 'dark' ? 'bg-slate-900/60' : 'bg-slate-100'}>
                                        <tr>
                                            <th className="px-3 py-2">PDR</th>
                                            <th className="px-3 py-2">Ingress evidence</th>
                                            <th className="px-3 py-2">FAR</th>
                                            <th className="px-3 py-2">Egress evidence</th>
                                            <th className="px-3 py-2">Path / selector</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rules.map(rule => (
                                            <TunnelRuleRow
                                                key={`${rule.pdr_id}-${rule.far_id}`}
                                                rule={rule}
                                                theme={theme}
                                            />
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    )}

                    {hasTraffic && (
                        <section className={`rounded-xl border p-4 ${section}`}>
                            <h3 className={`mb-3 font-semibold ${textPrimary}`}>Correlated user-plane counters</h3>
                            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                                <Fact label="Uplink packets" value={session.packets_ul.toLocaleString('en-US')} mono theme={theme} />
                                <Fact label="Downlink packets" value={session.packets_dl.toLocaleString('en-US')} mono theme={theme} />
                                <Fact label="Uplink PDU bytes" value={formatBytes(session.bytes_ul)} mono theme={theme} />
                                <Fact label="Downlink PDU bytes" value={formatBytes(session.bytes_dl)} mono theme={theme} />
                            </div>
                        </section>
                    )}

                    {hasQoS && (
                        <section className={`rounded-xl border p-4 ${section}`}>
                            <h3 className={`mb-3 font-semibold ${textPrimary}`}>Observed QoS parameters</h3>
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                                {Boolean(session.mbr_ul_kbps) && <Fact label="MBR uplink" value={formatKbps(session.mbr_ul_kbps as number)} theme={theme} />}
                                {Boolean(session.mbr_dl_kbps) && <Fact label="MBR downlink" value={formatKbps(session.mbr_dl_kbps as number)} theme={theme} />}
                                {Boolean(session.gbr_ul_kbps) && <Fact label="GBR uplink" value={formatKbps(session.gbr_ul_kbps as number)} theme={theme} />}
                                {Boolean(session.gbr_dl_kbps) && <Fact label="GBR downlink" value={formatKbps(session.gbr_dl_kbps as number)} theme={theme} />}
                            </div>
                        </section>
                    )}

                    {(session.created_at || session.duration || session.last_packet_time || session.data_plane_status) && (
                        <section className={`rounded-xl border p-4 ${section}`}>
                            <h3 className={`mb-3 font-semibold ${textPrimary}`}>Observation state</h3>
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                                {session.created_at && (
                                    <Fact label="First observed" value={timestamp(session.created_at)} theme={theme} />
                                )}
                                {session.duration && <Fact label="Observed for" value={session.duration} theme={theme} />}
                                {session.last_packet_time && (
                                    <Fact label="Last correlated packet" value={timestamp(session.last_packet_time)} theme={theme} />
                                )}
                                {session.data_plane_status && (
                                    <Fact label="Data-plane state" value={session.data_plane_status} theme={theme} />
                                )}
                            </div>
                        </section>
                    )}
                </div>
            </div>
        </div>
    )
}

interface SessionTableProps {
    theme?: Theme
}

export default function SessionTable({ theme = 'dark' }: SessionTableProps) {
    const [sessions, setSessions] = useState<SessionInfo[]>([])
    const [selected, setSelected] = useState<SessionInfo>()
    const [search, setSearch] = useState('')
    const [sortField, setSortField] = useState<SortField>('created_at')
    const [sortAscending, setSortAscending] = useState(false)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string>()

    useEffect(() => {
        let mounted = true
        const load = async () => {
            try {
                const response = await fetchSessions()
                if (!mounted) return
                setSessions([
                    ...(response.sessions || []).map(value => ({ ...value, monitoring_state: 'active' as const })),
                    ...(response.stale_sessions || []).map(value => ({ ...value, monitoring_state: 'stale' as const })),
                    ...(response.pending_sessions || []).map(value => ({ ...value, monitoring_state: 'pending' as const })),
                    ...(response.failed_sessions || []).map(value => ({ ...value, monitoring_state: 'failed' as const })),
                    ...(response.unclassified_sessions || []),
                ])
                setError(undefined)
            } catch (reason) {
                if (mounted) setError(reason instanceof Error ? reason.message : 'Unable to load sessions')
            } finally {
                if (mounted) setLoading(false)
            }
        }
        load()
        const timer = window.setInterval(load, 2000)
        return () => {
            mounted = false
            window.clearInterval(timer)
        }
    }, [])

    const visible = useMemo(() => {
        const term = search.trim().toLowerCase()
        const result = sessions.filter(session => !term || sessionSearchText(session).includes(term))
        result.sort((left, right) => {
            let comparison = 0
            if (sortField === 'packets') {
                comparison = (left.packets_ul + left.packets_dl) - (right.packets_ul + right.packets_dl)
            } else {
                comparison = (left[sortField] || '').localeCompare(right[sortField] || '')
            }
            return sortAscending ? comparison : -comparison
        })
        return result
    }, [sessions, search, sortField, sortAscending])

    const card = theme === 'dark'
        ? 'bg-slate-800/70 border-slate-700 hover:border-cyan-500/50'
        : 'bg-white border-slate-200 hover:border-cyan-500/50'
    const textPrimary = theme === 'dark' ? 'text-white' : 'text-slate-900'
    const textSecondary = theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
    const input = theme === 'dark'
        ? 'bg-slate-800 border-slate-700 text-white'
        : 'bg-white border-slate-300 text-slate-900'

    const changeSort = (field: SortField) => {
        if (sortField === field) {
            setSortAscending(value => !value)
        } else {
            setSortField(field)
            setSortAscending(false)
        }
    }

    if (loading && sessions.length === 0) {
        return <div className={`py-16 text-center ${textSecondary}`}>Loading observed PFCP sessions…</div>
    }

    if (error && sessions.length === 0) {
        return <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-red-400">{error}</div>
    }

    return (
        <div className="space-y-4">
            <div className="flex flex-col gap-3">
                <input
                    value={search}
                    onChange={event => setSearch(event.target.value)}
                    placeholder="Search observed IDs, UE/UPF IPs, F-SEIDs, TEIDs, DNN or PFCP rules"
                    className={`w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-cyan-500 ${input}`}
                />
                <div className="flex flex-wrap gap-2">
                    {([
                        ['created_at', 'First observed'],
                        ['observation_id', 'Observation ID'],
                        ['ue_ip', 'UE IP'],
                        ['packets', 'Packets'],
                    ] as [SortField, string][]).map(([field, label]) => (
                        <button
                            type="button"
                            key={field}
                            onClick={() => changeSort(field)}
                            className={`rounded-md border px-2.5 py-1 text-xs ${sortField === field
                                ? 'border-cyan-500/50 bg-cyan-500/15 text-cyan-400'
                                : `${theme === 'dark' ? 'border-slate-700' : 'border-slate-300'} ${textSecondary}`
                                }`}
                        >
                            {label}{sortField === field ? (sortAscending ? ' ↑' : ' ↓') : ''}
                        </button>
                    ))}
                </div>
            </div>

            {visible.length === 0 ? (
                <div className={`rounded-lg border py-12 text-center ${theme === 'dark' ? 'border-slate-700' : 'border-slate-200'} ${textSecondary}`}>
                    {search ? 'No session observation matches this search.' : 'No PFCP session observations are available.'}
                </div>
            ) : (
                <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                    {visible.map(session => {
                        const ruleCount = session.flow_rules?.length || 0
                        const localTEIDCount = new Set(session.local_f_teids || []).size
                        const source = evidenceSource(session)
                        return (
                            <button
                                type="button"
                                key={session.observation_id}
                                onClick={() => setSelected(session)}
                                className={`rounded-xl border p-4 text-left transition-colors ${card}`}
                            >
                                <div className="flex items-start justify-between gap-3">
                                    <div>
                                        <div className={`font-mono text-lg font-semibold ${session.ue_ip ? 'text-cyan-400' : textPrimary}`}>
                                            {session.ue_ip || session.observation_id}
                                        </div>
                                        <div className={`mt-0.5 font-mono text-xs ${textSecondary}`}>
                                            Observation ID {session.observation_id}
                                        </div>
                                    </div>
                                    {sessionStateLabel(session) && (
                                        <span className={`rounded-full border px-2 py-1 text-xs ${sessionStateClass(session)}`}>
                                            {sessionStateLabel(session)}
                                        </span>
                                    )}
                                </div>

                                <div className={`mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-sm ${textSecondary}`}>
                                    {session.cp_seid && (
                                        <div>
                                            <div className="text-xs">CP F-SEID</div>
                                            <div className={`font-mono ${textPrimary}`}>{session.cp_seid}</div>
                                        </div>
                                    )}
                                    {session.up_seid && (
                                        <div>
                                            <div className="text-xs">UP F-SEID</div>
                                            <div className={`font-mono ${textPrimary}`}>{session.up_seid}</div>
                                        </div>
                                    )}
                                    {session.upf_ip && (
                                        <div>
                                            <div className="text-xs">PFCP UPF endpoint</div>
                                            <div className={`font-mono ${textPrimary}`}>{session.upf_ip}</div>
                                        </div>
                                    )}
                                    {session.dnn && (
                                        <div>
                                            <div className="text-xs">DNN</div>
                                            <div className={textPrimary}>{session.dnn}</div>
                                        </div>
                                    )}
                                    {ruleCount > 0 && (
                                        <div>
                                            <div className="text-xs">Observed PDR/FAR rules</div>
                                            <div className={textPrimary}>{ruleCount}</div>
                                        </div>
                                    )}
                                    {localTEIDCount > 0 && (
                                        <div>
                                            <div className="text-xs">Local F-TEIDs</div>
                                            <div className={textPrimary}>{localTEIDCount}</div>
                                        </div>
                                    )}
                                </div>

                                {source && (
                                    <div className={`mt-3 border-t pt-2 text-xs ${theme === 'dark' ? 'border-slate-700' : 'border-slate-200'} ${session.source === 'pfcp' ? textSecondary : 'text-amber-400'}`}>
                                        {source}
                                    </div>
                                )}
                            </button>
                        )
                    })}
                </div>
            )}

            {selected && <SessionDetail session={selected} onClose={() => setSelected(undefined)} theme={theme} />}
        </div>
    )
}
