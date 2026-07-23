import type { TopologyLink, TopologyNode } from '../services/api'

export const TOPOLOGY_LAYERS: TopologyNode['type'][] = ['ue', 'gnb', 'upf', 'dn']

type NodesByType = Record<TopologyNode['type'], TopologyNode[]>

function normalizedRank(index: number, count: number): number {
    return count <= 1 ? 0.5 : index / (count - 1)
}

function currentRanks(nodesByType: NodesByType): Map<string, number> {
    const ranks = new Map<string, number>()
    TOPOLOGY_LAYERS.forEach(type => {
        const nodes = nodesByType[type]
        nodes.forEach((node, index) => {
            ranks.set(node.id, normalizedRank(index, nodes.length))
        })
    })
    return ranks
}

/**
 * Orders each fixed topology layer with iterative barycentric sweeps.
 *
 * The API determines which links and nodes exist. This function changes only
 * visual ordering, using actual adjacency to keep connected nodes aligned and
 * minimize crossings between adjacent layers.
 */
export function orderTopologyLayers(
    nodes: TopologyNode[],
    links: TopologyLink[],
): NodesByType {
    const nodesByType: NodesByType = { ue: [], gnb: [], upf: [], dn: [] }
    const typeByID = new Map<string, TopologyNode['type']>()
    const adjacency = new Map<string, Set<string>>()

    nodes.forEach(node => {
        nodesByType[node.type].push(node)
        typeByID.set(node.id, node.type)
        adjacency.set(node.id, new Set())
    })
    TOPOLOGY_LAYERS.forEach(type => {
        nodesByType[type].sort((left, right) => left.id.localeCompare(right.id))
    })
    links.forEach(link => {
        if (!typeByID.has(link.source) || !typeByID.has(link.target)) return
        adjacency.get(link.source)?.add(link.target)
        adjacency.get(link.target)?.add(link.source)
    })

    const layerIndex = new Map(TOPOLOGY_LAYERS.map((type, index) => [type, index]))

    const reorder = (type: TopologyNode['type'], direction: 'left' | 'right') => {
        const nodesInLayer = nodesByType[type]
        if (nodesInLayer.length < 2) return

        const ranks = currentRanks(nodesByType)
        const ownLayer = layerIndex.get(type) as number
        const scored = nodesInLayer.map((node, stableIndex) => {
            const neighborRanks = [...(adjacency.get(node.id) || [])]
                .filter(neighborID => {
                    const neighborType = typeByID.get(neighborID)
                    if (!neighborType) return false
                    const neighborLayer = layerIndex.get(neighborType) as number
                    return direction === 'left'
                        ? neighborLayer < ownLayer
                        : neighborLayer > ownLayer
                })
                .map(neighborID => ranks.get(neighborID))
                .filter((rank): rank is number => rank !== undefined)

            return {
                node,
                stableIndex,
                hasAdjacentEvidence: neighborRanks.length > 0,
                score: neighborRanks.length > 0
                    ? neighborRanks.reduce((sum, rank) => sum + rank, 0) / neighborRanks.length
                    : normalizedRank(stableIndex, nodesInLayer.length),
            }
        })

        scored.sort((left, right) => {
            const scoreDifference = left.score - right.score
            if (Math.abs(scoreDifference) > 1e-9) return scoreDifference
            if (left.hasAdjacentEvidence !== right.hasAdjacentEvidence) {
                return left.hasAdjacentEvidence ? -1 : 1
            }
            return left.stableIndex - right.stableIndex ||
                left.node.id.localeCompare(right.node.id)
        })
        nodesByType[type] = scored.map(entry => entry.node)
    }

    // Alternating sweeps allow both upstream and downstream evidence to
    // influence ordering while remaining deterministic for equal scores.
    for (let iteration = 0; iteration < 6; iteration++) {
        for (let index = 1; index < TOPOLOGY_LAYERS.length; index++) {
            reorder(TOPOLOGY_LAYERS[index], 'left')
        }
        for (let index = TOPOLOGY_LAYERS.length - 2; index >= 0; index--) {
            reorder(TOPOLOGY_LAYERS[index], 'right')
        }
    }

    return nodesByType
}
