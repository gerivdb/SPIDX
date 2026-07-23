//! SPIDX-CORE — Types de base du noyau déterministe de réécriture de graphes
//!
//! Invariants fondamentaux :
//! - **Canonicalisation** : toute structure admet une forme binaire déterministe (hash Merkle root)
//! - **Transformation pure** : `apply(graph, patch) -> new_graph` sans effets de bord
//! - **Rejeu bit-identique** : `replay(WAL) == current_root` vérifiable en continu

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use blake3;

/// Identifiant unique et canonique d'un nœud
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

impl NodeId {
    pub const fn new(id: u64) -> Self { Self(id) }
}

/// Identifiant unique et canonique d'une arête
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub u64);

impl EdgeId {
    pub const fn new(id: u64) -> Self { Self(id) }
}

/// Identifiant de zone (sous-graphe nommé)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub u64);

/// Hash Blake3 de 32 octets - utilisé pour tous les hashs canoniques
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn zero() -> Self { Self([0; 32]) }
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    
    /// Hash d'une structure sérialisable
    pub fn of<T: Serialize>(value: &T) -> Self {
        let mut hasher = blake3::Hasher::new();
        let bytes = bincode::serialize(value).expect("serialization");
        hasher.update(&bytes);
        Self(*hasher.finalize().as_bytes())
    }
}

/// Attributs de nœud (clé-valeur typés)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeAttrs(pub BTreeMap<String, AttrValue>);

/// Valeur d'attribut (typage simple pour canonicalisation)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttrValue {
    Bool(bool),
    U64(u64),
    I64(i64),
    String(String),
    Bytes(Vec<u8>),
    Hash(Hash),
}

/// Nœud du graphe
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub zone: Option<ZoneId>,
    pub attrs: NodeAttrs,
    /// Hash canonique du nœud (calculé après canonicalisation)
    #[serde(skip)]
    pub hash: Option<Hash>,
}

impl Node {
    pub fn new(id: NodeId) -> Self {
        Self { id, zone: None, attrs: NodeAttrs(BTreeMap::new()), hash: None }
    }
    
    pub fn with_attrs(mut self, attrs: NodeAttrs) -> Self {
        self.attrs = attrs; self
    }
    
    pub fn with_zone(mut self, zone: ZoneId) -> Self {
        self.zone = Some(zone); self
    }
}

/// Arête du graphe
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub src: NodeId,
    pub dst: NodeId,
    pub label: String,
    pub attrs: NodeAttrs,
    #[serde(skip)]
    pub hash: Option<Hash>,
}

impl Edge {
    pub fn new(id: EdgeId, src: NodeId, dst: NodeId, label: String) -> Self {
        Self { id, src, dst, label, attrs: NodeAttrs(BTreeMap::new()), hash: None }
    }
}

/// Zone (sous-graphe nommé avec métadonnées)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Zone {
    pub id: ZoneId,
    pub name: String,
    pub node_ids: BTreeSet<NodeId>,
    pub edge_ids: BTreeSet<EdgeId>,
    pub parent: Option<ZoneId>,
    #[serde(skip)]
    pub hash: Option<Hash>,
}

/// Graphe complet avec structure hiérarchique (zones)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graph {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<EdgeId, Edge>,
    pub zones: BTreeMap<ZoneId, Zone>,
    /// Prochain ID disponible pour allocation déterministe
    pub next_node_id: u64,
    pub next_edge_id: u64,
    pub next_zone_id: u64,
    /// Hash racine du graphe (Merkle root de tous les composants)
    #[serde(skip)]
    pub root_hash: Option<Hash>,
}

impl Graph {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            zones: BTreeMap::new(),
            next_node_id: 1,
            next_edge_id: 1,
            next_zone_id: 1,
            root_hash: None,
        }
    }
    
    /// Alloue un ID nœud déterministe
    pub fn alloc_node_id(&mut self) -> NodeId {
        let id = NodeId::new(self.next_node_id);
        self.next_node_id += 1;
        id
    }
    
    /// Alloue un ID arête déterministe
    pub fn alloc_edge_id(&mut self) -> EdgeId {
        let id = EdgeId::new(self.next_edge_id);
        self.next_edge_id += 1;
        id
    }
    
    /// Alloue un ID zone déterministe
    pub fn alloc_zone_id(&mut self) -> ZoneId {
        let id = ZoneId(self.next_zone_id);
        self.next_zone_id += 1;
        id
    }
    
    pub fn add_node(&mut self, mut node: Node) -> NodeId {
        if node.id == NodeId(0) { node.id = self.alloc_node_id(); }
        self.nodes.insert(node.id, node);
        node.id
    }
    
    pub fn add_edge(&mut self, mut edge: Edge) -> EdgeId {
        if edge.id == EdgeId(0) { edge.id = self.alloc_edge_id(); }
        self.edges.insert(edge.id, edge);
        edge.id
    }
    
    pub fn add_zone(&mut self, mut zone: Zone) -> ZoneId {
        if zone.id == ZoneId(0) { zone.id = self.alloc_zone_id(); }
        self.zones.insert(zone.id, zone);
        zone.id
    }
    
    /// Canonicalise le graphe (trie, calcule hashs, produit root_hash)
    pub fn canonicalize(&mut self) -> Hash {
        // 1. Canonicaliser chaque nœud (hash de ses attributs triés)
        for node in self.nodes.values_mut() {
            node.hash = Some(Hash::of(&CanonicalNode {
                id: node.id,
                zone: node.zone,
                attrs: &node.attrs,
            }));
        }
        
        // 2. Canonicaliser chaque arête
        for edge in self.edges.values_mut() {
            edge.hash = Some(Hash::of(&CanonicalEdge {
                id: edge.id,
                src: edge.src,
                dst: edge.dst,
                label: &edge.label,
                attrs: &edge.attrs,
            }));
        }
        
        // 3. Canonicaliser chaque zone (hash des IDs triés + hash des enfants)
        for zone in self.zones.values_mut() {
            zone.hash = Some(Hash::of(&CanonicalZone {
                id: zone.id,
                name: &zone.name,
                node_ids: &zone.node_ids,
                edge_ids: &zone.edge_ids,
                parent: zone.parent,
            }));
        }
        
        // 4. Hash racine = hash de tous les hashs de composants triés
        let mut component_hashes: Vec<Hash> = Vec::new();
        component_hashes.extend(self.nodes.values().map(|n| n.hash.unwrap()));
        component_hashes.extend(self.edges.values().map(|e| e.hash.unwrap()));
        component_hashes.extend(self.zones.values().map(|z| z.hash.unwrap()));
        component_hashes.sort();
        
        self.root_hash = Some(Hash::of(&component_hashes));
        self.root_hash.unwrap()
    }
    
    /// Vérifie l'intégrité (hashs correspondants)
    pub fn verify(&self) -> Result<(), String> {
        let mut g = self.clone();
        let computed = g.canonicalize();
        if self.root_hash != Some(computed) {
            return Err(format!("Root hash mismatch: expected {:?}, got {:?}", self.root_hash, computed));
        }
        Ok(())
    }
}

/// Structures pour canonicalisation (sans hash circulaire)
#[derive(Serialize)]
struct CanonicalNode<'a> {
    id: NodeId,
    zone: Option<ZoneId>,
    attrs: &'a NodeAttrs,
}

#[derive(Serialize)]
struct CanonicalEdge<'a> {
    id: EdgeId,
    src: NodeId,
    dst: NodeId,
    label: &'a str,
    attrs: &'a NodeAttrs,
}

#[derive(Serialize)]
struct CanonicalZone<'a> {
    id: ZoneId,
    name: &'a str,
    node_ids: &'a BTreeSet<NodeId>,
    edge_ids: &'a BTreeSet<EdgeId>,
    parent: Option<ZoneId>,
}

impl Default for Graph {
    fn default() -> Self { Self::new() }
}

// Re-exports publics
pub use self::{Node, Edge, Zone, Graph, NodeId, EdgeId, ZoneId, Hash, NodeAttrs, AttrValue};