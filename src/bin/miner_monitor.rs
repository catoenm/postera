//! TUI for monitoring mining progress

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use postera::crypto::note::{EncryptedNote, ViewingKey};
use postera::wallet::ShieldedWallet;
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use reqwest::Client;
use serde::Deserialize;
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const DECIMALS: u64 = 9;
const MAX_RECENT_BLOCKS: usize = 50;
const RECENT_DISPLAY_BLOCKS: usize = 20;
const REQUEST_TIMEOUT_SECS: u64 = 5;
const UI_REFRESH_SECS: u64 = 1;

#[derive(Parser)]
#[command(name = "postera-miner-monitor")]
#[command(about = "TUI for monitoring Postera mining progress")]
struct Cli {
    /// Wallet file
    #[arg(short, long, default_value = "wallet.json")]
    wallet: String,

    /// Node URL
    #[arg(short, long, default_value = "http://localhost:8333")]
    node: String,
}

#[derive(Deserialize)]
struct ChainInfo {
    height: u64,
    latest_hash: String,
    difficulty: u64,
    next_difficulty: u64,
    commitment_count: u64,
    nullifier_count: u64,
}

#[derive(Deserialize)]
struct BlockResponse {
    hash: String,
    height: u64,
    prev_hash: String,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
    tx_count: usize,
    commitment_root: String,
    nullifier_root: String,
    transactions: Vec<String>,
    coinbase_reward: u64,
    total_fees: u64,
    coinbase_ephemeral_pk: String,
    coinbase_ciphertext: String,
}

struct BlockInfo {
    height: u64,
    hash: String,
    timestamp: u64,
    reward: u64,
    is_mine: bool,
}

struct MiningStats {
    current_height: u64,
    current_difficulty: u64,
    last_block_time: Option<u64>,
    mining_start_time: Instant,
    recent_blocks: Vec<BlockInfo>,
    lifetime_blocks_won: u64,
    lifetime_pstr_earned: u64,
    session_blocks_won: u64,
    session_pstr_earned: u64,
}

impl MiningStats {
    fn new() -> Self {
        Self {
            current_height: 0,
            current_difficulty: 0,
            last_block_time: None,
            mining_start_time: Instant::now(),
            recent_blocks: Vec::new(),
            lifetime_blocks_won: 0,
            lifetime_pstr_earned: 0,
            session_blocks_won: 0,
            session_pstr_earned: 0,
        }
    }

    fn format_pstr(&self, amount: u64) -> String {
        let whole = amount / 10u64.pow(DECIMALS as u32);
        let frac = amount % 10u64.pow(DECIMALS as u32);
        if frac == 0 {
            format!("{} PSTR", whole)
        } else {
            let frac_str = format!("{:09}", frac);
            let trimmed = frac_str.trim_end_matches('0');
            if trimmed.is_empty() {
                format!("{} PSTR", whole)
            } else {
                format!("{}.{} PSTR", whole, trimmed)
            }
        }
    }

    fn pstr_per_hour(&self) -> f64 {
        let elapsed_hours = self.mining_start_time.elapsed().as_secs_f64() / 3600.0;
        if elapsed_hours > 0.0 {
            (self.session_pstr_earned as f64 / 10f64.powi(DECIMALS as i32)) / elapsed_hours
        } else {
            0.0
        }
    }

    fn total_earned(&self) -> u64 {
        self.lifetime_pstr_earned
    }

    fn total_blocks_won(&self) -> u64 {
        self.lifetime_blocks_won
    }

    fn current_block_elapsed(&self) -> Option<Duration> {
        self.last_block_time.map(|t| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Duration::from_secs(now.saturating_sub(t))
        })
    }
}

async fn fetch_chain_info(client: &Client, node_url: &str) -> Result<ChainInfo> {
    let url = format!("{}/chain/info", node_url);
    let response = client.get(&url).send().await?;
    let info: ChainInfo = response.json().await?;
    Ok(info)
}

async fn fetch_block(client: &Client, node_url: &str, height: u64) -> Result<BlockResponse> {
    let url = format!("{}/block/height/{}", node_url, height);
    let response = client.get(&url).send().await?;
    let block: BlockResponse = response.json().await?;
    Ok(block)
}

fn check_if_mine(block: &BlockResponse, viewing_key: &ViewingKey, pk_hash: [u8; 32]) -> bool {
    let ephemeral_pk = hex::decode(&block.coinbase_ephemeral_pk).ok();
    let ciphertext = hex::decode(&block.coinbase_ciphertext).ok();

    if let (Some(epk), Some(ct)) = (ephemeral_pk, ciphertext) {
        let encrypted_note = EncryptedNote {
            ciphertext: ct,
            ephemeral_pk: epk,
        };

        if let Some(note) = viewing_key.decrypt_note(&encrypted_note) {
            return note.recipient_pk_hash == pk_hash;
        }
    }
    false
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    wallet_path: &str,
    node_url: &str,
) -> Result<()> {
    let (quit_tx, mut quit_rx) = mpsc::unbounded_channel::<()>();
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(key)) => {
                let is_ctrl_c =
                    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        let _ = quit_tx.send(());
                        break;
                    }
                    _ if is_ctrl_c => {
                        let _ = quit_tx.send(());
                        break;
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });

    // Load wallet
    let wallet = ShieldedWallet::load(wallet_path).context("Failed to load wallet")?;
    let pk_hash = wallet.pk_hash();
    // Create viewing key from pk_hash (for decrypting coinbase)
    let viewing_key = ViewingKey::from_pk_hash(pk_hash);
    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .context("Failed to build HTTP client")?;
    let mut stats = MiningStats::new();
    let mut last_checked_height = 0u64;
    let mut session_start_height: Option<u64> = None;

    loop {
        if quit_rx.try_recv().is_ok() {
            return Ok(());
        }

        // Fetch chain info
        let info_result = tokio::select! {
            _ = quit_rx.recv() => return Ok(()),
            result = fetch_chain_info(&client, node_url) => result,
        };
        match info_result {
            Ok(info) => {
                if session_start_height.is_none() {
                    session_start_height = Some(info.height);
                }
                stats.current_height = info.height;
                stats.current_difficulty = info.difficulty;

                // Check for new blocks
                if info.height > last_checked_height {
                    for h in (last_checked_height + 1)..=info.height {
                        let block_result = tokio::select! {
                            _ = quit_rx.recv() => return Ok(()),
                            result = timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), fetch_block(&client, node_url, h)) => {
                                result.unwrap_or_else(|_| Err(anyhow::anyhow!("block fetch timeout")))
                            }
                        };
                        let block = match block_result {
                            Ok(block) => block,
                            Err(_) => break,
                        };

                        let is_mine = check_if_mine(&block, &viewing_key, pk_hash);

                        if is_mine {
                            stats.lifetime_blocks_won += 1;
                            stats.lifetime_pstr_earned += block.coinbase_reward;

                            if session_start_height
                                .map(|start| block.height > start)
                                .unwrap_or(false)
                            {
                                stats.session_blocks_won += 1;
                                stats.session_pstr_earned += block.coinbase_reward;
                            }
                        }

                        stats.recent_blocks.push(BlockInfo {
                            height: block.height,
                            hash: block.hash,
                            timestamp: block.timestamp,
                            reward: block.coinbase_reward,
                            is_mine,
                        });

                        // Keep only last blocks for display
                        if stats.recent_blocks.len() > MAX_RECENT_BLOCKS {
                            stats.recent_blocks.remove(0);
                        }

                        stats.last_block_time = Some(block.timestamp);
                        last_checked_height = block.height;
                    }
                }
            }
            Err(_) => {
                // Connection error - will show in UI as "Waiting for chain info..."
            }
        }

        // Draw UI
        terminal.draw(|f| ui(f, &stats))?;

        if quit_rx.try_recv().is_ok() {
            return Ok(());
        }

        // Refresh every second
        sleep(Duration::from_secs(UI_REFRESH_SECS)).await;
    }
}

fn ui(f: &mut Frame, stats: &MiningStats) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(12), // Current mining stats
            Constraint::Min(0),     // Block history
        ])
        .split(f.size());

    // Header
    let header = Paragraph::new("Postera Miner Monitor - Press 'q' to quit")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Current mining stats
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // Left: Current block info
    let current_block_text = if stats.current_height > 0 {
        let elapsed = stats
            .current_block_elapsed()
            .map(|d| format!("{:.1}s", d.as_secs_f64()))
            .unwrap_or_else(|| "0.0s".to_string());

        vec![
            Line::from(vec![
                Span::styled("Current Block: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{}", stats.current_height + 1),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Difficulty: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{} bits", stats.current_difficulty),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Time Elapsed: ", Style::default().fg(Color::Yellow)),
                Span::styled(elapsed, Style::default().fg(Color::White)),
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "Connecting to node...",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let current_block = Paragraph::new(current_block_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Mining Status"),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(current_block, stats_chunks[0]);

    // Right: Earnings (total + session)
    let earnings_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Length(8)])
        .split(stats_chunks[1]);

    let total_earnings_text = vec![
        Line::from(vec![
            Span::styled("Blocks Won: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}", stats.total_blocks_won()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Earned: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                stats.format_pstr(stats.total_earned()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let total_earnings = Paragraph::new(total_earnings_text)
        .block(Block::default().borders(Borders::ALL).title("Lifetime"))
        .wrap(Wrap { trim: true });
    f.render_widget(total_earnings, earnings_chunks[0]);

    let session_earnings_text = vec![
        Line::from(vec![
            Span::styled("Blocks Won: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}", stats.session_blocks_won),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total Earned: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                stats.format_pstr(stats.session_pstr_earned),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("PSTR/Hour: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{:.4}", stats.pstr_per_hour()),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Uptime: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format_duration(stats.mining_start_time.elapsed()),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let session_earnings = Paragraph::new(session_earnings_text)
        .block(Block::default().borders(Borders::ALL).title("Session"))
        .wrap(Wrap { trim: true });
    f.render_widget(session_earnings, earnings_chunks[1]);

    // Block history
    let mut block_elapsed: Vec<Option<u64>> = Vec::with_capacity(stats.recent_blocks.len());
    for (idx, block) in stats.recent_blocks.iter().enumerate() {
        if idx == 0 {
            block_elapsed.push(None);
        } else {
            let prev = &stats.recent_blocks[idx - 1];
            block_elapsed.push(Some(block.timestamp.saturating_sub(prev.timestamp)));
        }
    }

    let recent_blocks: Vec<ListItem> = stats
        .recent_blocks
        .iter()
        .enumerate()
        .rev()
        .take(RECENT_DISPLAY_BLOCKS)
        .map(|(idx, block)| {
            let mine_indicator = if block.is_mine {
                Span::styled(
                    "✓ ",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("✗ ", Style::default().fg(Color::Red))
            };

            let reward_text = format!(" +{}", stats.format_pstr(block.reward));
            let reward_style = if block.is_mine {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            let timestamp = DateTime::<Utc>::from_timestamp(block.timestamp as i64, 0)
                .map(|dt| dt.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "?".to_string());
            let elapsed = block_elapsed
                .get(idx)
                .and_then(|v| *v)
                .map(|secs| format_duration(Duration::from_secs(secs)))
                .unwrap_or_else(|| "--:--:--".to_string());

            ListItem::new(vec![Line::from(vec![
                mine_indicator,
                Span::styled(
                    format!("#{} ", block.height),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("{}", &block.hash[..8]),
                    Style::default().fg(Color::White),
                ),
                Span::raw(" "),
                Span::styled(reward_text, reward_style),
                Span::raw(" "),
                Span::styled(timestamp, Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::styled(
                    format!("Δ {}", elapsed),
                    Style::default().fg(Color::DarkGray),
                ),
            ])])
        })
        .collect();

    let block_list = List::new(recent_blocks)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent Blocks"),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(block_list, chunks[2]);
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &cli.wallet, &cli.node).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}
