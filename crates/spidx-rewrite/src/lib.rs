//! SPIDX-REWRITE — Moteur de réécriture de graphes (pattern matching + application de patches)
//!
//! Responsabilités :
//! - Pattern matching sur graphes (règles CTULU compilées)
//! - Application de patches atomiques
//! - Génération de patches différentiels
//! - Composition de patches

use spidx_core::{Graph, Node, Edge, Zone, NodeId, EdgeId, ZoneId, Hash, Patch, PatchOp, NodeAttrs};
use spidx_canon::canonicalize;
use spidx_guard::{Guard, GuardContext, GuardResult};
use spidx_proof::Proof;
use thiserror::Error;
use bincode;
use std::collections::BTreeMap;

#[derive(Error, Debug)]
pub enum RewriteError {
    #[error("Pattern match failed: {0}")]
    PatternMatch(String),
    #[error("Guard failed: {0}")]
    GuardFailed(String),
    #[error("Patch application failed: {0}")]
    PatchApply(String),
    #[error("Canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Contexte d'exécution d'une réécriture
pub struct RewriteContext<'a> {
    pub guards: &'a [Box<dyn Guard>],
    pub rule_id: String,
    pub rule_version: u32,
    pub timestamp: u64,
}

/// Résultat d'une réécriture
pub struct RewriteResult {
    pub new_graph: Graph,
    pub patch: Patch,
    pub proof: Proof,
}

/// Applique une règle de réécriture à un graphe
pub fn apply_rule(
    graph: &Graph,
    pattern: &Pattern,
    replacement: &Replacement,
    ctx: &RewriteContext,
) -> Result<RewriteResult, RewriteError> {
    // 1. Pattern matching
    let matches = pattern.match_graph(graph)?;
    if matches.is_empty() {
        return Err(RewriteError::PatternMatch("No match found".into()));
    }
    
    // Pour v0 : premier match seulement
    let match_bindings = &matches[0];
    
    // 2. Vérifier les guards
    let guard_ctx = GuardContext { graph, bindings: match_bindings };
    for guard in ctx.guards {
        guard.check(&guard_ctx).map_err(|e| RewriteError::GuardFailed(e.to_string()))?;
    }
    
    // 3. Construire le patch
    let mut patch = Patch::new(graph.root_hash.unwrap_or_default());
    let mut new_graph = graph.clone();
    
    // Appliquer le remplacement
    replacement.apply(match_bindings, &mut new_graph, &mut patch)?;
    
    // 4. Canonicaliser le nouveau graphe
    canonicalize(&mut new_graph);
    
    // 5. Finaliser le patch
    patch.target_hash = new_graph.root_hash.unwrap_or_default();
    
    // 6. Générer la preuve
    let proof = Proof::new(
        ctx.rule_id.clone(),
        ctx.rule_version,
        graph.root_hash.unwrap_or_default(),
        patch.hash(),
        new_graph.root_hash.unwrap_or_default(),
        ctx.timestamp,
    );
    
    Ok(RewriteResult { new_graph, patch, proof })
}

/// Pattern de matching (côté gauche d'une règle)
pub struct Pattern {
    pub node_patterns: Vec<NodePattern>,
    pub edge_patterns: Vec<EdgePattern>,
    pub constraints: Vec<Constraint>,
}

#[derive(Clone, Debug)]
pub struct NodePattern {
    pub var_name: String,           // Variable de liaison (ex: "?x")
    pub required_attrs: NodeAttrs,  // Attributs obligatoires
    pub zone: Option<ZoneId>,       // Zone requise (optionnel)
}

#[derive(Clone, Debug)]
pub struct EdgePattern {
    pub src_var: String,            // Variable source
    pub dst_var: String,            // Variable destination
    pub label: String,
    pub required_attrs: NodeAttrs,
}

#[derive(Clone, Debug)]
pub enum Constraint {
    NotEqual(String, String),       // ?x != ?y
    InZone(String, ZoneId),         // ?x in zone
    HasAttr(String, String),        // ?x.has("attr")
}

impl Pattern {
    pub fn match_graph(&self, graph: &Graph) -> Result<Vec<BTreeMap<String, NodeId>>, RewriteError> {
        // Implémentation simplifiée pour v0
        // Vérifier que tous les patterns de nœuds matchent
        let mut bindings = BTreeMap::new();
        
        for np in &self.node_patterns {
            let mut found = false;
            for (nid, node) in &graph.nodes {
                if self.node_matches(node, np) {
                    if bindings.contains_key(&np.var_name) {
                        // Variable déjà liée - vérifier cohérence
                        if bindings[&np.var_name] != *nid {
                            continue;
                        }
                    } else {
                        bindings.insert(np.var_name.clone(), *nid);
                        found = true;
                        break;
                    }
                }
            }
            if !found && !bindings.contains_key(&np.var_name) {
                return Err(RewriteError::PatternMatch(
                    format!("Node pattern '{}' not matched", np.var_name)
                ));
            }
        }
        
        // Vérifier patterns d'arêtes
        for ep in &self.edge_patterns {
            let src = bindings.get(&ep.src_var).copied();
            let dst = bindings.get(&ep.dst_var).copied();
            let matched = graph.edges.values().any(|e| {
                e.src == src.unwrap_or(NodeId(0)) && e.dst == dst.unwrap_or(NodeId(0))
                    && e.label == ep.label
            });
            if !matched {
                return Err(RewriteError::PatternMatch(
                    format!("Edge pattern '{} -> {} ({})' not matched", ep.src_var, ep.dst_var, ep.label)
                ));
            }
        }
        
        Ok(vec![bindings])
    }
    
    fn node_matches(&self, node: &Node, pattern: &NodePattern) -> bool {
        // Vérifier zone
        if let Some(z) = pattern.zone { if node.zone != Some(z) { return false; } }
        // Vérifier attributs obligatoires
        for (k, v) in &pattern.required_attrs.0 {
            if node.attrs.0.get(k) != Some(v) { return false; }
        }
        true
    }
}

/// Remplacement (côté droit d'une règle)
pub struct Replacement {
    pub node_creations: Vec<NodeCreation>,
    pub edge_creations: Vec<EdgeCreation>,
    pub node_deletions: Vec<String>,  // Variables à supprimer
    pub edge_deletions: Vec<(String, String)>,
    pub attr_updates: Vec<AttrUpdate>,
}

#[derive(Clone, Debug)]
pub struct NodeCreation {
    pub var_name: String,
    pub attrs: NodeAttrs,
    pub zone: Option<ZoneId>,
}

#[derive(Clone, Debug)]
pub struct EdgeCreation {
    pub src_var: String,
    pub dst_var: String,
    pub label: String,
    pub attrs: NodeAttrs,
}

#[derive(Clone, Debug)]
pub struct AttrUpdate {
    pub var_name: String,
    pub attr_key: String,
    pub new_value: spidx_core::AttrValue,
}

impl Replacement {
    pub fn apply(
        &self,
        bindings: &BTreeMap<String, NodeId>,
        graph: &mut Graph,
        patch: &mut Patch,
    ) -> Result<(), RewriteError> {
        // 1. Suppressions de nœuds
        for var in &self.node_deletions {
            if let Some(&nid) = bindings.get(var) {
                if graph.nodes.remove(&nid).is_some() {
                    patch.ops.push(PatchOp::RemoveNode { id: nid });
                }
            }
        }
        
        // 2. Suppressions d'arêtes
        for (src_var, dst_var) in &self.edge_deletions {
            let src = bindings.get(src_var);
            let dst = bindings.get(dst_var);
            if let (Some(&s), Some(&d)) = (src, dst) {
                // Trouver et supprimer l'arête correspondante
                if let Some((eid, _)) = graph.edges.iter()
                    .find(|(_, e)| e.src == s && e.dst == d)
                    .map(|(id, e)| (*id, e.clone())) {
                    graph.edges.remove(&eid);
                    patch.ops.push(PatchOp::RemoveEdge { id: eid });
                }
            }
        }
        
        // 3. Mises à jour d'attributs
        for upd in &self.attr_updates {
            if let Some(&nid) = bindings.get(&upd.var_name) {
                if let Some(node) = graph.nodes.get_mut(&nid) {
                    let old = node.attrs.0.insert(upd.attr_key.clone(), upd.new_value.clone());
                    patch.ops.push(PatchOp::ModifyNodePayload { id: nid, new_payload: bincode::serialize(&upd.new_value).unwrap() });
                    if old.is_some() {
                        // Attribut existait déjà
                    }
                }
            }
        }
        
        // 3. Création de nœuds
        for nc in &self.node_creations {
            let mut node = Node::new(NodeId(0));
            node.attrs = nc.attrs.clone();
            node.zone = nc.zone;
            let nid = graph.add_node(node);
            patch.ops.push(PatchOp::AddNode { 
                id: nid, 
                node: graph.nodes[&nid].clone() 
            });
        }
        
        // 4. Création d'arêtes
        for ec in &self.edge_creations {
            let src = bindings.get(&ec.src_var);
            let dst = bindings.get(&ec.dst_var);
            if let (Some(&s), Some(&d)) = (src, dst) {
                let mut edge = Edge::new(EdgeId(0), s, d, ec.label.clone());
                edge.attrs = ec.attrs.clone();
                let eid = graph.add_edge(edge);
                patch.ops.push(PatchOp::AddEdge { 
                    id: eid, 
                    edge: graph.edges[&eid].clone() 
                });
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spidx_core::{Graph, Node, NodeId, ZoneId, NodeAttrs, AttrValue};
    
    #[test]
    fn test_simple_rewrite() {
        let mut g = Graph::new();
        let n = g.add_node(Node::new(NodeId(1)).with_attrs(NodeAttrs::from([("type", AttrValue::String("A".into()))])));
        
        let pattern = Pattern {
            node_patterns: vec![NodePattern { var_name: "?x".into(), required_attrs: NodeAttrs::from([("type", AttrValue::String("A".into()))]), zone: None }],
            edge_patterns: vec![],
            constraints: vec![],
        };
        
        let replacement = Replacement {
            node_creations: vec![NodeCreation { var_name: "?y".into(), attrs: NodeAttrs::from([("type", AttrValue::String("B".into()))]), zone: None }],
            edge_creations: vec![EdgeCreation { src_var: "?x".into(), dst_var: "?y".into(), label: "derives".into(), attrs: NodeAttrs::new() }],
            node_deletions: vec![],
            edge_deletions: vec![],
            attr_updates: vec![],
        };
        
        let ctx = RewriteContext { guards: &[], rule_id: "test".into(), rule_version: 1, timestamp: 123456 };
        
        // TODO: test complet après implémentation complète
    }
}