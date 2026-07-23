import { orderTopologyLayers } from '../src/utils/topologyLayout'
import type { TopologyLink, TopologyNode } from '../src/services/api'

const nodes: TopologyNode[] = [
    { id: 'ue', type: 'ue', label: 'UE' },
    { id: 'gnb', type: 'gnb', label: 'gNB' },
    { id: '10.100.200.2', type: 'upf', label: 'PSA-UPF' },
    { id: '10.100.200.3', type: 'upf', label: 'I-UPF' },
    { id: 'DN:1.0.0.1/32', type: 'dn', label: 'DN: 1.0.0.1/32' },
    { id: 'DN:internet', type: 'dn', label: 'DN: internet' },
]

const links: TopologyLink[] = [
    { source: 'ue', target: 'gnb', type: 'radio' },
    { source: 'gnb', target: '10.100.200.3', type: 'n3' },
    { source: '10.100.200.3', target: '10.100.200.2', type: 'n9' },
    { source: '10.100.200.3', target: 'DN:1.0.0.1/32', type: 'n6' },
    { source: '10.100.200.2', target: 'DN:internet', type: 'n6' },
]

function assertCrossingFree(
    orderedNodes: ReturnType<typeof orderTopologyLayers>,
    candidateLinks: TopologyLink[],
) {
    const upfRank = new Map(orderedNodes.upf.map((node, index) => [node.id, index]))
    const dnRank = new Map(orderedNodes.dn.map((node, index) => [node.id, index]))
    const n6Links = candidateLinks.filter(link => link.type === 'n6')

    for (let left = 0; left < n6Links.length; left++) {
        for (let right = left + 1; right < n6Links.length; right++) {
            const first = n6Links[left]
            const second = n6Links[right]
            const sourceDelta = (upfRank.get(first.source) as number) -
                (upfRank.get(second.source) as number)
            const targetDelta = (dnRank.get(first.target) as number) -
                (dnRank.get(second.target) as number)
            if (sourceDelta * targetDelta < 0) {
                throw new Error(`crossing remains between ${first.target} and ${second.target}`)
            }
        }
    }
}

const ordered = orderTopologyLayers(nodes, links)
assertCrossingFree(ordered, links)

const reversed = orderTopologyLayers([...nodes].reverse(), [...links].reverse())
const signature = (value: ReturnType<typeof orderTopologyLayers>) =>
    value.upf.map(node => node.id).join(',') + '|' +
    value.dn.map(node => node.id).join(',')

if (signature(ordered) !== signature(reversed)) {
    throw new Error('layout ordering depends on API array order')
}

console.log(`topology layout verified: ${signature(ordered)}`)
