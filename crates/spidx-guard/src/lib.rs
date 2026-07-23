//! SPIDX-GUARD — Gardes de sécurité et d'invariants
//!
//! Chaque transformation doit passer ces gardes avant application :
//! - **Acyclicité** : pas de cycles introduits dans le graphe
//! - **P4-sparse** : pas de P4 induit (structure arachnide préservée)
//! - **Monotonie causale** : pas de violation d'ordre temporel
//! - **Politiques φ-CPS / TTL** : conformité aux seuils de robustesse

use spidx_core::{Graph, NodeId, EdgeId, ZoneId, Hash};
use std::collections::BTreeSet;

/// Contexte de vérification des gardes
pub struct GuardContext<'a> {
    pub graph: &'a Graph,
    pub bindings: &'a std::collections::BTreeMap<String, NodeId>,
}

/// Résultat d'une garde
pub type GuardResult = Result<(), GuardError>;

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("Cycle detected: {0}")]
    Cycle(String),
    #[error("P4-sparse violation: {0}")]
    P4Sparse(String),
    #[error("Causal monotonicity violated: {0}")]
    CausalMonotonicity(String),
    #[error("Policy violation (φ-CPS/TTL): {0}")]
    Policy(String),
    #[error("Guard check failed: {0}")]
    Other(String),
}

/// Trait pour les gardes personnalisés
pub trait Guard: Send + Sync {
    fn check(&self, ctx: &GuardContext) -> GuardResult;
    fn name(&self) -> &str { "guard" }
}

/// Garde d'acyclicité (pas de cycles dirigés)
pub struct AcyclicGuard;

impl Guard for AcyclicGuard {
    fn name(&self) -> &str { "acyclic" }
    
    fn check(&self, ctx: &GuardContext) -> GuardResult {
        if has_directed_cycle(ctx.graph) {
            return Err(GuardError::Cycle("Directed cycle detected in graph".into()));
        }
        Ok(())
    }
}

/// Garde P4-sparse (structure arachnide - pas de P4 induit)
/// Voir arXiv:2302.00112
pub struct P4SparseGuard;

impl Guard for P4SparseGuard {
    fn name(&self) -> &str { "p4_sparse" }
    
    fn check(&self, ctx: &GuardContext) -> GuardResult {
        if has_induced_p4(ctx.graph) {
            return Err(GuardError::P4Sparse("Induced P4 path detected".into()));
        }
        Ok(())
    }
}

/// Garde de monotonie causale (pas de retour en arrière temporel)
pub struct CausalMonotonicGuard;

impl Guard for CausalMonotonicGuard {
    fn name(&self) -> &str { "causal_monotonic" }
    
    fn check(&self, ctx: &GuardContext) -> GuardResult {
        // Vérifier que les timestamps ne décroissent pas sur les chemins
        for edge in ctx.graph.edges.values() {
            let src_ts = ctx.graph.nodes[&edge.src].attrs.0.get("timestamp")
                .and_then(|v| match v { spidx_core::AttrValue::U64(t) => Some(*t), _ => None });
            let dst_ts = ctx.graph.nodes[&edge.dst].attrs.0.get("timestamp")
                .and_then(|v| match v { spidx_core::AttrValue::U64(t) => Some(*t), _ => None });
            
            if let (Some(s), Some(d)) = (src_ts, dst_ts) {
                if d < s {
                    return Err(GuardError::CausalMonotonicity(
                        format!("Causal timestamp violation: {} -> {} ({} < {})", edge.src, edge.dst, d, s)
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Garde de politique φ-CPS / TTL
pub struct PolicyGuard {
    pub phi_cps_threshold: f64,
    pub max_ttl: u64,
}

impl PolicyGuard {
    pub fn new(phi_cps_threshold: f64, max_ttl: u64) -> Self {
        Self { phi_cps_threshold, max_ttl }
    }
}

impl Guard for PolicyGuard {
    fn name(&self) -> &str { "policy" }
    
    fn check(&self, ctx: &GuardContext) -> GuardResult {
        // Calculer φ-CPS approximatif (densité de connexions inter-zones)
        let phi_cps = compute_phi_cps(ctx.graph);
        if phi_cps > self.phi_cps_threshold {
            return Err(GuardError::Policy(
                format!("φ-CPS threshold exceeded: {:.3} > {:.3}", phi_cps, self.phi_cps_threshold)
            ));
        }
        
        // Vérifier TTL (timestamp max - timestamp min)
        let timestamps: Vec<u64> = ctx.graph.nodes.values()
            .filter_map(|n| n.attrs.0.get("timestamp"))
            .filter_map(|v| match v { spidx_core::AttrValue::U64(t) => Some(*t), _ => None })
            .collect();
        
        if !timestamps.is_empty() {
            let min_ts = *timestamps.iter().min().unwrap();
            let max_ts = *timestamps.iter().max().unwrap();
            if max_ts - min_ts > self.max_ttl {
                return Err(GuardError::Policy(
                    format!("TTL exceeded: {} > {}", max_ts - min_ts, self.max_ttl)
                ));
            }
        }
        
        Ok(())
    }
}

/// Détecte les cycles dirigés (DFS)
fn has_directed_cycle(graph: &Graph) -> bool {
    let mut visited = BTreeSet::new();
    let mut rec_stack = BTreeSet::new();
    
    fn dfs(node: NodeId, graph: &Graph, visited: &mut BTreeSet<NodeId>, rec_stack: &mut BTreeSet<NodeId>) -> bool {
        visited.insert(node);
        rec_stack.insert(node);
        
        // Trouver les arêtes sortantes
        for edge in graph.edges.values() {
            if edge.src == node {
                if !visited.contains(&edge.dst) {
                    if dfs(edge.dst, graph, visited, rec_stack) { return true; }
                } else if rec_stack.contains(&edge.dst) {
                    return true; // Cycle détecté
                }
            }
        }
        
        rec_stack.remove(&node);
        false
    }
    
    for node in graph.nodes.keys() {
        if !visited.contains(node) {
            if dfs(*node, graph, &mut visited, &mut rec_stack) { return true; }
        }
    }
    false
}

/// Détecte P4 induit (chemin de 4 nœuds sans cordes)
/// Algorithme basé sur arXiv:2302.00112
fn has_induced_p4(graph: &Graph) -> bool {
    let nodes: Vec<_> = graph.nodes.keys().copied().collect();
    
    // Pour chaque triplet d'arêtes (a-b, b-c, c-d), vérifier qu'il n'y a pas d'arêtes a-c, b-d, a-d
    for &a in &nodes {
        for &b in &nodes {
            if a == b { continue; }
            if !edge_exists(graph, a, b) { continue; }
            
            for &c in &nodes {
                if c == a || c == b { continue; }
                if !edge_exists(graph, b, c) { continue; }
                
                for &d in &nodes {
                    if d == a || d == b || d == c { continue; }
                    if !edge_exists(graph, c, d) { continue; }
                    
                    // Vérifier qu'il n'y a pas d'arêtes "cordes"
                    if edge_exists(graph, a, c) { continue; }
                    if edge_exists(graph, b, d) { continue; }
                    if edge_exists(graph, a, d) { continue; }
                    
                    // P4 induit trouvé : a-b-c-d sans cordes
                    return true;
                }
            }
        }
    }
    false
}

fn edge_exists(graph: &Graph, src: NodeId, dst: NodeId) -> bool {
    graph.edges.values().any(|e| e.src == src && e.dst == dst)
}

/// Calcule φ-CPS approximatif (mesure de couplage inter-zones)
fn compute_phi_cps(graph: &Graph) -> f64 {
    let zones: Vec<_> = graph.zones.keys().copied().collect();
    if zones.len() < 2 { return 0.0; }
    
    let mut cross_edges = 0;
    let mut total_edges = graph.edges.len();
    
    for edge in graph.edges.values() {
        let src_zone = graph.nodes[&edge.src].zone;
        let dst_zone = graph.nodes[&edge.dst].zone;
        if src_zone != dst_zone && src_zone.is_some() && dst_zone.is_some() {
            cross_edges += 1;
        }
    }
    
    if total_edges == 0 { 0.0 } else { cross_edges as f64 / total_edges as f64 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spidx_core::{Graph, Node, NodeId, ZoneId, NodeAttrs, AttrValue};
    
    #[test]
    fn acyclic_guard_passes_on_dag() {
        let mut g = Graph::new();
        let n1 = g.add_node(Node::new(NodeId(1)));
        let n2 = g.add_node(Node::new(NodeId(2)));
        let n3 = g.add_node(Node::new(NodeId(3)));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(1), n1, n2, "next".into()));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(2), n2, n3, "next".into()));
        
        let ctx = GuardContext { graph: &g, bindings: &std::collections::BTreeMap::new() };
        assert!(AcyclicGuard.check(&ctx).is_ok());
    }
    
    #[test]
    fn acyclic_guard_fails_on_cycle() {
        let mut g = Graph::new();
        let n1 = g.add_node(Node::new(NodeId(1)));
        let n2 = g.add_node(Node::new(NodeId(2)));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(1), n1, n2, "next".into()));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(2), n2, n1, "prev".into()));
        
        let ctx = GuardContext { graph: &g, bindings: &std::collections::BTreeMap::new() };
        assert!(AcyclicGuard.check(&ctx).is_err());
    }
    
    #[test]
    fn p4_sparse_guard_passes_on_star() {
        // Star graph (P4-sparse)
        let mut g = Graph::new();
        let center = g.add_node(Node::new(NodeId(1)));
        for i in 2..=5 {
            let leaf = g.add_node(Node::new(NodeId(i)));
            g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(i as u64), center, leaf, "link".into()));
        }
        
        let ctx = GuardContext { graph: &g, bindings: &std::collections::BTreeMap::new() };
        assert!(P4SparseGuard.check(&ctx).is_ok());
    }
    
    #[test]
    fn p4_sparse_guard_fails_on_path4() {
        // Chemin de 4 nœuds (P4 induit)
        let mut g = Graph::new();
        let n1 = g.add_node(Node::new(NodeId(1)));
        let n2 = g.add_node(Node::new(NodeId(2)));
        let n3 = g.add_node(Node::new(NodeId(3)));
        let n4 = g.add_node(Node::new(NodeId(4)));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(1), n1, n2, "next".into()));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(2), n2, n3, "next".into()));
        g.add_edge(spidx_core::Edge::new(spidx_core::EdgeId(3), n3, n4, "next".into()));
        
        let ctx = GuardContext { graph: &g, bindings: &std::collections::BTreeMap::new() };
        assert!(P4SparseGuard.check(&ctx).is_err());
    }
}