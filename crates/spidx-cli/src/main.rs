//! SPIDX-CLI — Interface en ligne de commande
//!
//! Commandes :
//! - `spidx apply` : applique un patch à un graphe
//! - `spidx verify` : vérifie une preuve WAL
//! - `spidx replay` : rejoue un WAL complet
//! - `spidx diff` : diff entre deux graphes
//! - `spidx canon` : canonicalise un graphe

use spidx_core::{Graph, Hash, Patch, PatchOp, Node, NodeId, Edge, EdgeId, ZoneId, NodeAttrs, AttrValue};
use spidx_canon::canonicalize;
use spidx_wal::{Wal, WalEntry};
use spidx_proof::{Proof, ProofChain};
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "spidx", version, about = "SPIDX - Spider Graph Rewriting Kernel")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Applique un patch à un graphe
    Apply {
        #[arg(short, long)] graph: PathBuf,
        #[arg(short, long)] patch: PathBuf,
        #[arg(short, long)] output: PathBuf,
    },
    /// Vérifie une preuve WAL
    Verify {
        #[arg(short, long)] wal: PathBuf,
        #[arg(short, long)] snapshot: Option<u64>,
    },
    /// Rejoue un WAL complet
    Replay {
        #[arg(short, long)] wal: PathBuf,
        #[arg(short, long)] from_snapshot: Option<u64>,
        #[arg(short, long)] output: PathBuf,
    },
    /// Diff entre deux graphes
    Diff {
        #[arg(short, long)] graph1: PathBuf,
        #[arg(short, long)] graph2: PathBuf,
        #[arg(short, long)] output: PathBuf,
    },
    /// Canonicalise un graphe
    Canon {
        #[arg(short, long)] input: PathBuf,
        #[arg(short, long)] output: PathBuf,
    },
    /// Génère un graphe de test
    Gen {
        #[arg(short, long)] output: PathBuf,
        #[arg(short, long, default_value = "10")] nodes: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Apply { graph, patch, output } => cmd_apply(graph, patch, output),
        Commands::Verify { wal, snapshot } => cmd_verify(wal, snapshot),
        Commands::Replay { wal, from_snapshot, output } => cmd_replay(wal, from_snapshot, output),
        Commands::Diff { graph1, graph2, output } => cmd_diff(graph1, graph2, output),
        Commands::Canon { input, output } => cmd_canon(input, output),
        Commands::Gen { output, nodes } => cmd_gen(output, nodes),
    }
}

fn cmd_apply(graph_path: PathBuf, patch_path: PathBuf, output_path: PathBuf) -> Result<()> {
    let graph_data = fs::read(&graph_path)?;
    let mut graph: Graph = bincode::deserialize(&graph_data)?;
    
    let patch_data = fs::read(&patch_path)?;
    let patch: Patch = bincode::deserialize(&patch_data)?;
    
    // Appliquer le patch
    for op in &patch.ops {
        match op {
            PatchOp::AddNode { id, node } => {
                graph.add_node(node.clone());
            }
            PatchOp::RemoveNode { id } => {
                graph.nodes.remove(id);
            }
            PatchOp::AddEdge { id, edge } => {
                graph.add_edge(edge.clone());
            }
            PatchOp::RemoveEdge { id } => {
                graph.edges.remove(id);
            }
            PatchOp::ModifyNodePayload { id, new_payload } => {
                if let Some(node) = graph.nodes.get_mut(id) {
                    node.payload = new_payload.clone();
                }
            }
            PatchOp::ModifyEdgePayload { id, new_payload } => {
                if let Some(edge) = graph.edges.get_mut(id) {
                    edge.payload = new_payload.clone();
                }
            }
            _ => {}
        }
    }
    
    // Canonicaliser
    canonicalize(&mut graph);
    
    // Sauvegarder
    let out_data = bincode::serialize(&graph)?;
    fs::write(&output_path, out_data)?;
    
    println!("Applied patch. Root hash: {:?}", graph.root_hash);
    Ok(())
}

fn cmd_verify(wal_path: PathBuf, snapshot: Option<u64>) -> Result<()> {
    let wal = Wal::open(&wal_path, 1000)?;
    
    if let Some(seq) = snapshot {
        let graph = wal.replay_from_snapshot(seq)?;
        println!("Replayed from snapshot {}. Root hash: {:?}", seq, graph.root_hash);
    } else {
        let graph = wal.replay()?;
        println!("Full replay complete. Root hash: {:?}", graph.root_hash);
    }
    
    wal.verify()?;
    println!("WAL verification: PASSED");
    Ok(())
}

fn cmd_replay(wal_path: PathBuf, from_snapshot: Option<u64>, output_path: PathBuf) -> Result<()> {
    let wal = Wal::open(&wal_path, 1000)?;
    
    let graph = if let Some(seq) = from_snapshot {
        wal.replay_from_snapshot(seq)?
    } else {
        wal.replay()?
    };
    
    let out_data = bincode::serialize(&graph)?;
    fs::write(&output_path, out_data)?;
    
    println!("Replayed to {}. Root hash: {:?}", output_path.display(), graph.root_hash);
    Ok(())
}

fn cmd_diff(graph1_path: PathBuf, graph2_path: PathBuf, output_path: PathBuf) -> Result<()> {
    let g1_data = fs::read(&graph1_path)?;
    let mut g1: Graph = bincode::deserialize(&g1_data)?;
    
    let g2_data = fs::read(&graph2_path)?;
    let mut g2: Graph = bincode::deserialize(&g2_data)?;
    
    canonicalize(&mut g1);
    canonicalize(&mut g2);
    
    // Diff simple : nœuds/arêtes dans g2 mais pas dans g1
    let mut patch = Patch::new(g1.root_hash.unwrap_or_default());
    
    for (id, node) in &g2.nodes {
        if !g1.nodes.contains_key(id) {
            patch.ops.push(PatchOp::AddNode { id: *id, node: node.clone() });
        }
    }
    
    for (id, edge) in &g2.edges {
        if !g1.edges.contains_key(id) {
            patch.ops.push(PatchOp::AddEdge { id: *id, edge: edge.clone() });
        }
    }
    
    patch.target_hash = g2.root_hash.unwrap_or_default();
    
    let out_data = bincode::serialize(&patch)?;
    fs::write(&output_path, out_data)?;
    
    println!("Diff generated: {} ops", patch.ops.len());
    Ok(())
}

fn cmd_canon(input_path: PathBuf, output_path: PathBuf) -> Result<()> {
    let data = fs::read(&input_path)?;
    let mut graph: Graph = bincode::deserialize(&data)?;
    
    let hash = canonicalize(&mut graph);
    
    let out_data = bincode::serialize(&graph)?;
    fs::write(&output_path, out_data)?;
    
    println!("Canonicalized. Root hash: {:?}", hash);
    Ok(())
}

fn cmd_gen(output_path: PathBuf, num_nodes: usize) -> Result<()> {
    let mut graph = Graph::new();
    
    for i in 1..=num_nodes {
        let mut node = Node::new(NodeId(i as u64));
        node.attrs.0.insert("type".into(), AttrValue::String("test".into()));
        node.attrs.0.insert("index".into(), AttrValue::U64(i as u64));
        graph.add_node(node);
    }
    
    // Ajouter quelques arêtes
    for i in 1..num_nodes {
        graph.add_edge(Edge::new(
            EdgeId(i as u64),
            NodeId(i as u64),
            NodeId((i + 1) as u64),
            "next".into(),
        ));
    }
    
    canonicalize(&mut graph);
    
    let out_data = bincode::serialize(&graph)?;
    fs::write(&output_path, out_data)?;
    
    println!("Generated graph with {} nodes. Root hash: {:?}", num_nodes, graph.root_hash);
    Ok(())
}