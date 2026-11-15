use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;

use crate::engine::topology;
use crate::error::{Error, Result};
use crate::kill::free_port;
use crate::model::{format_bytes, parse_port_spec, KillOpts, ProcessNode, QueryOpts, Topology};

struct Row {
    label: String,
    detail: String,
    port: Option<u16>,
}

struct App {
    data: Topology,
    outbound: bool,
    filter: String,
    filtering: bool,
    selected: usize,
    detail: bool,
    confirm: bool,
    status: String,
    fetched: Instant,
}

pub fn run() -> Result<i32> {
    if !io::stdout().is_terminal() {
        return Err(Error::new("whose watch needs a terminal"));
    }
    enable_raw_mode().map_err(|err| Error::new(err.to_string()))?;
    let guard = RawGuard;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|err| Error::new(err.to_string()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|err| Error::new(err.to_string()))?;
    let mut app = App {
        data: fetch().unwrap_or_else(|err| empty_topology(err.to_string())),
        outbound: false,
        filter: String::new(),
        filtering: false,
        selected: 0,
        detail: false,
        confirm: false,
        status: "j/down move  / filter  enter detail  o outbound  k kill  q quit".to_string(),
        fetched: Instant::now(),
    };
    let code = loop {
        if app.fetched.elapsed() >= Duration::from_secs(1) && !app.confirm {
            match fetch() {
                Ok(data) => {
                    app.data = data;
                    app.fetched = Instant::now();
                }
                Err(err) => app.status = err.to_string(),
            }
        }
        let rows = rows_of(&app);
        if app.selected >= rows.len() && !rows.is_empty() {
            app.selected = rows.len() - 1;
        }
        terminal
            .draw(|frame| draw(frame, &app, &rows))
            .map_err(|err| Error::new(err.to_string()))?;
        if !event::poll(Duration::from_millis(200)).map_err(|err| Error::new(err.to_string()))? {
            continue;
        }
        let event = event::read().map_err(|err| Error::new(err.to_string()))?;
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break 0;
        }
        if app.confirm {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    app.confirm = false;
                    if let Some(port) = rows.get(app.selected).and_then(|row| row.port) {
                        app.status = kill_port(port);
                        app.fetched = Instant::now() - Duration::from_secs(2);
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    app.confirm = false;
                    app.status = "kill cancelled".to_string();
                }
                _ => {}
            }
            continue;
        }
        if app.filtering {
            match key.code {
                KeyCode::Esc => {
                    app.filtering = false;
                    app.filter.clear();
                }
                KeyCode::Enter => app.filtering = false,
                KeyCode::Backspace => {
                    app.filter.pop();
                }
                KeyCode::Char(ch) => app.filter.push(ch),
                _ => {}
            }
            app.selected = 0;
            continue;
        }
        match key.code {
            KeyCode::Char('q') => break 0,
            KeyCode::Char('/') => app.filtering = true,
            KeyCode::Enter => app.detail = !app.detail,
            KeyCode::Char('o') => {
                app.outbound = !app.outbound;
                app.selected = 0;
                app.detail = false;
            }
            KeyCode::Char('k') => {
                if app.outbound {
                    app.status = "kill applies to listeners; press o to leave outbound".to_string();
                } else if rows.get(app.selected).and_then(|row| row.port).is_some() {
                    app.confirm = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if app.selected + 1 < rows.len() {
                    app.selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('u') => {
                app.selected = app.selected.saturating_sub(1);
            }
            KeyCode::Char('r') => app.fetched = Instant::now() - Duration::from_secs(2),
            _ => {}
        }
    };
    drop(terminal);
    drop(guard);
    Ok(code)
}

fn fetch() -> Result<Topology> {
    topology(&QueryOpts {
        show_secrets: false,
    })
}

fn empty_topology(warning: String) -> Topology {
    Topology {
        socket_source: "unavailable".to_string(),
        projects: Vec::new(),
        warnings: vec![warning],
    }
}

fn kill_port(port: u16) -> String {
    let spec = match parse_port_spec(&port.to_string()) {
        Ok(spec) => spec,
        Err(err) => return err.to_string(),
    };
    match free_port(
        spec,
        KillOpts {
            yes: true,
            force: false,
            grace_ms: 2000,
            interactive: false,
        },
    ) {
        Ok(report) => report.message,
        Err(err) => err.to_string(),
    }
}

fn rows_of(app: &App) -> Vec<Row> {
    let mut rows = Vec::new();
    for project in &app.data.projects {
        for process in &project.processes {
            if app.outbound {
                for flow in &process.outbound {
                    rows.push(Row {
                        label: format!(
                            "{}  {} {} {} -> {}",
                            project.label, flow.protocol, flow.state, flow.local, flow.remote
                        ),
                        detail: process_detail(process, &project.label),
                        port: None,
                    });
                }
            } else {
                for listen in &process.listens {
                    let warning = listen.warning.as_deref().unwrap_or("");
                    rows.push(Row {
                        label: format!(
                            "{}  :{} {} {} {} pid {}",
                            project.label,
                            listen.port,
                            listen.protocol,
                            listen.state,
                            listen.local,
                            process.pid
                        ),
                        detail: format!("{}\n{warning}", process_detail(process, &project.label)),
                        port: Some(listen.port),
                    });
                }
            }
        }
    }
    if app.filter.is_empty() {
        return rows;
    }
    let needle = app.filter.to_ascii_lowercase();
    rows.into_iter()
        .filter(|row| {
            row.label.to_ascii_lowercase().contains(&needle)
                || row.detail.to_ascii_lowercase().contains(&needle)
        })
        .collect()
}

fn process_detail(process: &ProcessNode, project: &str) -> String {
    let chain = process.ancestry.join(" → ");
    let supervisor = process
        .supervisor
        .as_deref()
        .map(|name| {
            let stop = process.stop.as_deref().unwrap_or("");
            format!("supervisor {name} {stop}")
        })
        .unwrap_or_default();
    let env = process
        .env
        .iter()
        .map(|item| format!("{}={}", item.key, item.value))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{project}\n{}  up {}  rss {}\n{chain}\n{supervisor}\n{env}",
        process.cmdline,
        process.uptime,
        format_bytes(process.rss_bytes)
    )
}

fn draw(frame: &mut ratatui::Frame, app: &App, rows: &[Row]) {
    let detail_len = if app.detail { 12 } else { 3 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(detail_len),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let title = if app.filtering {
        format!("filter /{}", app.filter)
    } else if app.outbound {
        format!("whose outbound  {}", app.data.socket_source)
    } else {
        format!("whose  {}", app.data.socket_source)
    };
    frame.render_widget(Paragraph::new(title), chunks[0]);
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| ListItem::new(Line::from(Span::raw(row.label.clone()))))
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(if app.outbound {
                    "outbound"
                } else {
                    "listeners"
                }),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, chunks[1], &mut state);
    let detail = if app.confirm {
        "kill this listener's process group? y / n".to_string()
    } else {
        rows.get(app.selected)
            .map(|row| row.detail.clone())
            .unwrap_or_else(|| "no sockets".to_string())
    };
    let detail_style = if app.confirm {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(detail)
            .style(detail_style)
            .block(Block::default().borders(Borders::ALL).title("detail"))
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
    let footer = if app.data.warnings.is_empty() {
        app.status.clone()
    } else {
        format!("{}  {}", app.status, app.data.warnings[0])
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

struct RawGuard;

impl Drop for RawGuard {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = execute!(out, LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = disable_raw_mode();
    }
}
