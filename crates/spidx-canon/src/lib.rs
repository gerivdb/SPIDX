//! SPIDX-CANON — Canonicalisation déterministe de graphes
//!
//! Responsabilités :
//! - Normalisation des IDs (compacts, séquentiels, déterministes)
//! - Tri canonique des collections (BTreeMap/BTreeSet)
//! - Calcul du hash racine Merkle (Blake3)
//! - Sérialisation binaire déterministe (bincode)

use spidx_core::{Graph, Node, Edge, Zone, NodeId, EdgeId, ZoneId, Hash, NodeAttrs};
use blake3;
use bincode;
use std::collections::BTreeMap;

/// Canonicalisateur d'état - transforme un graphe brut en forme canonique
pub struct Canonicalizer {
    /// Mapping ancien ID -> nouveau ID canonique
    node_id_map: BTreeMap<NodeId, NodeId>,
    edge_id_map: BTreeMap<EdgeId, EdgeId>,
    zone_id_map: BTreeMap<ZoneId, ZoneId>,
    next_node_id: u64,
    next_edge_id: u64,
    next_zone_id: u64,
}

impl Canonicalizer {
    pub fn new() -> Self {
        Self {
            node_id_map: BTreeMap::new(),
            edge_id_map: BTreeMap::new(),
            zone_id_map: BTreeMap::new(),
            next_node_id: 1,
            next_edge_id: 1,
            next_zone_id: 0, // Zone 0 = root
        }
    }
    
    /// Canonicalise un graphe complet
    pub fn canonicalize(&mut self, graph: &mut Graph) -> Hash {
        // 1. Remapper les IDs de nœuds (ordre par hash des attributs)
        self.remap_node_ids(graph);
        
        // 2. Remapper les IDs d'arêtes
        self.remap_edge_ids(graph);
        
        // 3. Remapper les IDs de zones
        self.remap_zone_ids(graph);
        
        // 4. Recalculer tous les hashs
        self.recompute_hashes(graph);
        
        // 5. Calculer le hash racine
        self.compute_root_hash(graph)
    }
    
    fn remap_node_ids(&mut self, graph: &mut Graph) {
        // Collecter tous les nœuds avec leur hash d'attributs
        let mut nodes: Vec<_> = graph.nodes.drain().collect();
        
        // Trier par hash d'attributs (déterministe)
        nodes.sort_by(|(_, a), (_, b)| {
            let ha = a.attrs_hash().unwrap_or_default();
            let hb = b.attrs_hash().unwrap_or_default();
            ha.cmp(&hb)
        });
        
        // Assigner nouveaux IDs séquentiels
        let mut new_nodes = BTreeMap::new();
        for (old_id, mut node) in nodes {
            let new_id = if old_id == NodeId(0) {
                let nid = NodeId(self.next_node_id);
                self.next_node_id += 1;
                nid
            } else {
                *self.node_id_map.entry(old_id).or_insert_with(|| {
                    let nid = NodeId(self.next_node_id);
                    self.next_node_id += 1;
                    nid
                })
            };
            self.node_id_map.insert(old_id, new_id);
            node.id = new_id;
            // Remapper zone si présente
            if let Some(zone) = node.zone {
                node.zone = Some(*self.zone_id_map.entry(zone).or_insert_with(|| {
                    let zid = ZoneId(self.next_zone_id);
                    self.next_zone_id += 1;
                    zid
                }));
            }
            new_nodes.insert(new_id, node);
        }
        graph.nodes = new_nodes;
    }
    
    fn remap_edge_ids(&mut self, graph: &mut Graph) {
        let mut edges: Vec<_> = graph.edges.drain().collect();
        
        edges.sort_by(|(_, a), (_, b)| {
            // Trier par (src, dst, label, hash_attrs)
            let ha = a.attrs_hash().unwrap_or_default();
            let hb = b.attrs_hash().unwrap_or_default();
            a.src.cmp(&b.src)
                .then(a.dst.cmp(&b.dst))
                .then(a.label.cmp(&b.label))
                .then(ha.cmp(&hb))
        });
        
        let mut new_edges = BTreeMap::new();
        for (old_id, mut edge) in edges {
            let new_id = if old_id == EdgeId(0) {
                let eid = EdgeId(self.next_edge_id);
                self.next_edge_id += 1;
                eid
            } else {
                *self.edge_id_map.entry(old_id).or_insert_with(|| {
                    let eid = EdgeId(self.next_edge_id);
                    self.next_edge_id += 1;
                    eid
                })
            };
            self.edge_id_map.insert(old_id, new_id);
            edge.id = new_id;
            // Remapper src/dst
            edge.src = *self.node_id_map.get(&edge.src).unwrap_or(&edge.src);
            edge.dst = *self.node_id_map.get(&edge.dst).unwrap_or(&edge.dst);
            // Remapper zone
            if let Some(zone) = edge.zone {
                edge.zone = Some(*self.zone_id_map.entry(zone).or_insert_with(|| {
                    let zid = ZoneId(self.next_zone_id);
                    self.next_zone_id += 1;
                    zid
                }));
            }
            new_edges.insert(new_id, edge);
        }
        graph.edges = new_edges;
    }
    
    fn remap_zone_ids(&mut self, graph: &mut Graph) {
        let mut zones: Vec<_> = graph.zones.drain().collect();
        zones.sort_by_key(|(_, z)| z.id);
        
        let mut new_zones = BTreeMap::new();
        for (old_id, mut zone) in zones {
            let new_id = if old_id == ZoneId(0) {
                ZoneId(0) // Root zone garde ID 0
            } else {
                *self.zone_id_map.entry(old_id).or_insert_with(|| {
                    let zid = ZoneId(self.next_zone_id);
                    self.next_zone_id += 1;
                    zid
                })
            };
            self.zone_id_map.insert(old_id, new_id);
            zone.id = new_id;
            // Remapper parent
            zone.parent = zone.parent.and_then(|p| self.zone_id_map.get(&p).copied());
            // Remapper node_ids
            zone.node_ids = zone.node_ids.iter()
                .filter_map(|nid| self.node_id_map.get(nid).copied())
                .collect();
            // Remapper edge_ids
            zone.edge_ids = zone.edge_ids.iter()
                .filter_map(|eid| self.edge_id_map.get(eid).copied())
                .collect();
            new_zones.insert(new_id, zone);
        }
        // Assurer zone root
        new_zones.entry(ZoneId(0)).or_insert_with(|| Zone::root());
        graph.zones = new_zones;
    }
    
    fn recompute_hashes(&self, graph: &mut Graph) {
        // Hash nœuds
        for node in graph.nodes.values_mut() {
            node.hash = Some(self.hash_node(node));
        }
        // Hash arêtes
        for edge in graph.edges.values_mut() {
            edge.hash = Some(self.hash_edge(edge));
        }
        // Hash zones (ordre topologique pour gérer parents)
        let mut zone_order: Vec<_> = graph.zones.keys().copied().collect();
        zone_order.sort_by_key(|z| graph.zones[z].depth());
        for zid in zone_order {
            if let Some(zone) = graph.zones.get_mut(&zid) {
                zone.hash = Some(self.hash_zone(zone, &graph.zones));
            }
        }
    }
    
    fn hash_node(&self, node: &Node) -> Hash {
        #[derive(serde::Serialize)]
        struct CanonicalNode<'a> {
            id: NodeId,
            zone: Option<ZoneId>,
            attrs: &'a NodeAttrs,
        }
        let cn = CanonicalNode { id: node.id, zone: node.zone, attrs: &node.attrs };
        Hash::of(&cn)
    }
    
    fn hash_edge(&self, edge: &Edge) -> Hash {
        #[derive(serde::Serialize)]
        struct CanonicalEdge<'a> {
            id: EdgeId,
            src: NodeId,
            dst: NodeId,
            label: &'a str,
            attrs: &'a NodeAttrs,
        }
        let ce = CanonicalEdge { id: edge.id, src: edge.src, dst: edge.dst, label: &edge.label, attrs: &edge.attrs };
        Hash::of(&ce)
    }
    
    fn hash_zone(&self, zone: &Zone, all_zones: &BTreeMap<ZoneId, Zone>) -> Hash {
        #[derive(serde::Serialize)]
        struct CanonicalZone<'a> {
            id: ZoneId,
            name: &'a str,
            node_ids: &'a BTreeSet<NodeId>,
            edge_ids: &'a BTreeSet<EdgeId>,
            parent_hash: Option<Hash>,
        }
        let parent_hash = zone.parent.and_then(|p| all_zones.get(&p).and_then(|z| z.hash));
        let cz = CanonicalZone {
            id: zone.id,
            name: &zone.name,
            node_ids: &zone.node_ids,
            edge_ids: &zone.edge_ids,
            parent_hash,
        };
        Hash::of(&cz)
    }
    
    fn compute_root_hash(&self, graph: &Graph) -> Hash {
        let mut hasher = blake3::Hasher::new();
        // Hash tous les nœuds (triés par ID)
        for node in graph.nodes.values() {
            hasher.update(&bincode::serialize(&node.hash.unwrap()).unwrap());
        }
        // Hash toutes les arêtes
        for edge in graph.edges.values() {
            hasher.update(&bincode::serialize(&edge.hash.unwrap()).unwrap());
        }
        // Hash toutes les zones
        for zone in graph.zones.values() {
            hasher.update(&bincode::serialize(&zone.hash.unwrap()).unwrap());
        }
        Hash::from(hasher.finalize().as_bytes())
    }
}

impl Default for Canonicalizer {
    fn default() -> Self { Self::new() }
}

/// Fonction utilitaire pour canonicaliser rapidement
pub fn canonicalize(graph: &mut Graph) -> Hash {
    let mut c = Canonicalizer::new();
    c.canonicalize(graph)
}

/// Vérifie qu'un graphe est déjà canonique
pub fn is_canonical(graph: &Graph) -> bool {
    let mut g = graph.clone();
    let new_hash = canonicalize(&mut g);
    graph.root_hash == Some(new_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spidx_core::{Graph, Node, Edge, Zone, NodeId, EdgeId, ZoneId, NodeAttrs, AttrValue};
    
    #[test]
    fn test_canonicalization_deterministic() {
        let mut g1 = Graph::new();
        let n1 = Node::new(NodeId(100), ZoneId(1), NodeAttrs::from([("type", AttrValue::String("test".into()))]));
        let n2 = Node::new(NodeId(50), ZoneId(1), NodeAttrs::from([("type", AttrValue::String("test".into()))]));
        g1.add_node(n1);
        g1.add_node(n2);
        canonicalize(&mut g1);
        
        let mut g2 = Graph::new();
        let n1 = Node::new(NodeId(50), ZoneId(1), NodeAttrs::from([("type", AttrValue::String("test".into()))]));
        let n2 = Node::new(NodeId(100), ZoneId(1), NodeAttrs::from([("type", AttrValue::String("test".into()))]));
        g2.add_node(n1);
        g2.add_node(n2);
        canonicalize(&mut g2);
        
        assert_eq!(g1.root_hash, g2.root_hash);
        // IDs doivent être séquentiels à partir de 1
        assert_eq!(g1.nodes.keys().copied().collect::<Vec<_>>(), vec![NodeId(1), NodeId(2)]);
    }
}