//! Shared clients use a deliberately bounded JSON surface, never owner sockets.
use std::io::{self, IsTerminal};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::{
    event::{
        self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    DefaultTerminal,
};
use serde_json::{json, Value};

use super::broker;

struct Screen;
impl Screen {
    fn enter() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "this screen requires an interactive terminal; use --json or explicit grant flags",
            ));
        }
        enable_raw_mode()?;
        if let Err(error) = execute!(
            io::stdout(),
            EnterAlternateScreen,
            event::EnableMouseCapture,
            event::EnableBracketedPaste
        ) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            event::DisableMouseCapture,
            event::DisableBracketedPaste,
            LeaveAlternateScreen
        );
    }
}

fn terminal() -> io::Result<DefaultTerminal> {
    ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))
}
fn text(value: &Value, field: &str) -> String {
    value[field]
        .as_str()
        .unwrap_or_default()
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}
fn rows(value: &Value, field: &str) -> Vec<Value> {
    value[field].as_array().cloned().unwrap_or_default()
}
fn selected_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}
fn quit(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL)
}
fn frame_rows(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area)
        .to_vec()
}

#[derive(Clone)]
struct Pane {
    id: String,
    title: String,
    control: bool,
}
fn panes(spaces: &Value) -> Vec<Pane> {
    rows(spaces, "workspaces")
        .into_iter()
        .flat_map(|space| {
            let control = space["role"] == "control" || space["role"] == "owner";
            rows(&space, "tabs").into_iter().flat_map(move |tab| {
                let space_label = text(&space, "label");
                rows(&tab, "panes").into_iter().map(move |pane| Pane {
                    id: text(&pane, "id"),
                    title: format!(
                        "{} / {} / {}",
                        space_label,
                        text(&tab, "label"),
                        text(&pane, "label")
                    ),
                    control,
                })
            })
        })
        .collect()
}

pub(super) fn attach(socket: &Path, owner: u32) -> io::Result<()> {
    let status = broker::request(socket, owner, "status", json!({}))?;
    let _screen = Screen::enter()?;
    let mut terminal = terminal()?;
    let mut pane_list = Vec::<Pane>::new();
    let mut selection = 0usize;
    let mut output = String::new();
    let mut message = String::new();
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut prefix = false;
    let mut sidebar = Rect::default();
    let mut list_state = ListState::default();
    loop {
        if last_poll.elapsed() >= Duration::from_millis(250) {
            // Clear all cached content before reconnect/revalidation. Failure
            // leaves an empty screen, never the last authorised terminal text.
            let previous = pane_list.get(selection).map(|p| p.id.clone());
            output.clear();
            match broker::request(socket, owner, "spaces", json!({})) {
                Ok(spaces) => {
                    pane_list = panes(&spaces);
                    selection = previous
                        .and_then(|id| pane_list.iter().position(|p| p.id == id))
                        .unwrap_or(0);
                    if let Some(pane) = pane_list.get(selection) {
                        match broker::request(
                            socket,
                            owner,
                            "read",
                            json!({"pane_id":pane.id,"lines":terminal.size()?.height.saturating_sub(6).max(1)}),
                        ) {
                            Ok(read) => {
                                output = read["text"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .chars()
                                    .filter(|character| {
                                        !character.is_control() || matches!(character, '\n' | '\t')
                                    })
                                    .collect();
                                message.clear();
                            }
                            Err(error) => message = error.to_string(),
                        }
                    }
                }
                Err(error) => {
                    pane_list.clear();
                    message = error.to_string();
                }
            }
            last_poll = Instant::now();
        }
        terminal.draw(|frame| {
            let bands=frame_rows(frame.area());
            frame.render_widget(Paragraph::new(format!("Herdr shared · {} · execution account: {}\nF6 next pane · F9 split · Ctrl+b then q detach · Ctrl+q quit",text(&status,"caller_name"),text(&status,"execution_user"))),bands[0]);
            let columns=Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(28),Constraint::Percentage(72)]).split(bands[1]);
            sidebar=columns[0];
            let items=pane_list.iter().enumerate().map(|(index,pane)| ListItem::new(format!("{} {}",if pane.control {"●"} else {"◉"},pane.title)).style(selected_style(index==selection))).collect::<Vec<_>>();
            list_state.select(Some(selection));
            frame.render_stateful_widget(List::new(items).block(Block::default().borders(Borders::ALL).title("Shared spaces / panes")),columns[0],&mut list_state);
            let empty="No spaces have been shared with this account.";
            let title=if pane_list.get(selection).is_some_and(|p|p.control) {"Terminal · Control (owner privileges)"} else {"Terminal · View"};
            frame.render_widget(Paragraph::new(if pane_list.is_empty() {empty} else {&output}).block(Block::default().borders(Borders::ALL).title(title)),columns[1]);
            frame.render_widget(Paragraph::new(message.as_str()).style(Style::default().fg(Color::Yellow)),bands[2]);
        })?;
        if !event::poll(Duration::from_millis(40))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if quit(key) {
                    break;
                }
                if prefix {
                    prefix = false;
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('n') => {
                            if !pane_list.is_empty() {
                                selection = (selection + 1) % pane_list.len();
                            }
                            last_poll = Instant::now() - Duration::from_secs(1);
                            continue;
                        }
                        _ => {}
                    }
                } else if key.code == KeyCode::Char('b')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    prefix = true;
                    continue;
                }
                if key.code == KeyCode::F(6) {
                    if !pane_list.is_empty() {
                        selection = (selection + 1) % pane_list.len();
                    }
                    output.clear();
                    last_poll = Instant::now() - Duration::from_secs(1);
                    continue;
                }
                let Some(pane) = pane_list.get(selection).filter(|p| p.control) else {
                    continue;
                };
                if key.code == KeyCode::F(9) {
                    match broker::request(
                        socket,
                        owner,
                        "split",
                        json!({"pane_id":pane.id,"direction":"right"}),
                    ) {
                        Ok(_) => message = "Pane created.".into(),
                        Err(error) => message = error.to_string(),
                    }
                    last_poll = Instant::now() - Duration::from_secs(1);
                    continue;
                }
                let result = match key.code {
                    KeyCode::Char(character)
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        broker::request(
                            socket,
                            owner,
                            "input",
                            json!({"pane_id":pane.id,"text":character.to_string()}),
                        )
                    }
                    _ => match api_key(key) {
                        Some(key) => broker::request(
                            socket,
                            owner,
                            "keys",
                            json!({"pane_id":pane.id,"keys":[key]}),
                        ),
                        None => continue,
                    },
                };
                if let Err(error) = result {
                    message = error.to_string();
                    output.clear();
                }
                last_poll = Instant::now() - Duration::from_secs(1);
            }
            Event::Paste(paste) => {
                if let Some(pane) = pane_list.get(selection).filter(|p| p.control) {
                    if let Err(error) = broker::request(
                        socket,
                        owner,
                        "input",
                        json!({"pane_id":pane.id,"text":paste}),
                    ) {
                        message = error.to_string();
                    }
                }
            }
            Event::Mouse(mouse)
                if mouse.kind == MouseEventKind::Down(MouseButton::Left)
                    && sidebar.contains((mouse.column, mouse.row).into()) =>
            {
                let index =
                    usize::from(mouse.row.saturating_sub(sidebar.y + 1)) + list_state.offset();
                if index < pane_list.len() {
                    selection = index;
                    output.clear();
                    last_poll = Instant::now() - Duration::from_secs(1);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn api_key(key: KeyEvent) -> Option<String> {
    let base = match key.code {
        KeyCode::Enter => "Enter".into(),
        KeyCode::Backspace => "Backspace".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::BackTab => "BackTab".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Up => "Up".into(),
        KeyCode::Down => "Down".into(),
        KeyCode::Left => "Left".into(),
        KeyCode::Right => "Right".into(),
        KeyCode::Home => "Home".into(),
        KeyCode::End => "End".into(),
        KeyCode::Delete => "Delete".into(),
        KeyCode::Insert => "Insert".into(),
        KeyCode::PageUp => "PageUp".into(),
        KeyCode::PageDown => "PageDown".into(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::F(n) => format!("F{n}"),
        _ => return None,
    };
    let mut result = String::new();
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        result.push_str("ctrl+");
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        result.push_str("alt+");
    }
    if key.modifiers.contains(KeyModifiers::SHIFT) && !matches!(key.code, KeyCode::Char(_)) {
        result.push_str("shift+");
    }
    result.push_str(&base);
    Some(result)
}

pub(super) fn admin(socket: &Path, owner: u32) -> io::Result<()> {
    let status = broker::request(socket, owner, "status", json!({}))?;
    let state = broker::request(socket, owner, "grants.get", json!({}))?;
    let users = broker::request(socket, owner, "users", json!({}))?;
    let space_state = broker::request(socket, owner, "spaces", json!({}))?;
    let _screen = Screen::enter()?;
    let mut terminal = terminal()?;
    let mut accounts = rows(&users, "accounts");
    for grant in rows(&state, "grants") {
        if !accounts
            .iter()
            .any(|account| account["uid"] == grant["uid"])
        {
            accounts
                .push(json!({"uid":grant["uid"],"name":grant["account_name"],"unresolved":true}));
        }
    }
    let spaces = rows(&space_state, "workspaces");
    let mut draft = rows(&state, "grants");
    let revision = state["revision"].clone();
    let mut user_index = 0usize;
    let mut space_index = 0usize;
    let mut user_focus = true;
    let mut query = None::<String>;
    let mut confirm = false;
    let mut confirm_disable = false;
    let mut acknowledged = false;
    let mut message = String::new();
    let mut areas = Vec::<Rect>::new();
    let mut user_state = ListState::default();
    let mut space_state = ListState::default();
    loop {
        terminal.draw(|frame| {
            let bands=frame_rows(frame.area());
            frame.render_widget(Paragraph::new("Space access · Owner administration\nTab switch column · arrows select · Space change role · s save · r revoke user · d disable sharing · / search · q cancel"),bands[0]);
            areas=Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(38),Constraint::Percentage(62)]).split(bands[1]).to_vec();
            let list=accounts.iter().enumerate().map(|(i,user)|ListItem::new(format!("{} (UID {}){}",text(user,"name"),user["uid"],if user["unresolved"]==true {" [unresolved]"} else {""})).style(selected_style(i==user_index&&user_focus))).collect::<Vec<_>>();
            user_state.select(Some(user_index));
            frame.render_stateful_widget(List::new(list).block(Block::default().borders(Borders::ALL).title("OS accounts")),areas[0],&mut user_state);
            let selected=accounts.get(user_index);
            let matrix=spaces.iter().enumerate().map(|(i,space)| {
                let role=if selected.is_some_and(|user|user["uid"].as_u64()==Some(u64::from(owner))) {"Owner".into()} else {selected.and_then(|user|draft.iter().find(|grant|grant["uid"]==user["uid"]&&grant["workspace_id"]==space["id"])).map(|grant|text(grant,"role")).unwrap_or_else(||"No access".into())};
                ListItem::new(Line::from(vec![Span::raw(format!("{:<25}",text(space,"label"))),Span::styled(role,Style::default().fg(Color::Yellow))])).style(selected_style(i==space_index&&!user_focus))
            }).collect::<Vec<_>>();
            space_state.select(Some(space_index));
            frame.render_stateful_widget(List::new(matrix).block(Block::default().borders(Borders::ALL).title("Space permissions (draft)")),areas[1],&mut space_state);
            let footer=if confirm_disable {"Disable sharing for all participants? y / n (running terminals continue)".into()} else if confirm {format!("Control lets this user run commands as {} and access that account's files and credentials. Grant Control? y / n",text(&status,"execution_user"))} else if let Some(query)=&query {format!("OS account search: {query} (Enter search, Esc cancel)")} else {message.clone()};
            frame.render_widget(Paragraph::new(footer).wrap(Wrap {trim:false}).style(Style::default().fg(Color::Yellow)),bands[2]);
        })?;
        let event = event::read()?;
        if let Event::Mouse(mouse) = event {
            if mouse.kind == MouseEventKind::Down(MouseButton::Left) && areas.len() == 2 {
                for (column, area) in areas.iter().enumerate() {
                    if area.contains((mouse.column, mouse.row).into()) {
                        let index = usize::from(mouse.row.saturating_sub(area.y + 1))
                            + if column == 0 {
                                user_state.offset()
                            } else {
                                space_state.offset()
                            };
                        if column == 0 && index < accounts.len() {
                            user_index = index;
                            user_focus = true;
                        }
                        if column == 1 && index < spaces.len() {
                            space_index = index;
                            user_focus = false;
                        }
                    }
                }
            }
            continue;
        }
        let Event::Key(key) = event else { continue };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if quit(key) {
            break;
        }
        if confirm_disable {
            if key.code == KeyCode::Char('y') {
                broker::request(socket, owner, "disable", json!({}))?;
                break;
            }
            confirm_disable = false;
            continue;
        }
        if confirm {
            if key.code == KeyCode::Char('y') {
                acknowledged = true;
                if let (Some(user), Some(space)) =
                    (accounts.get(user_index), spaces.get(space_index))
                {
                    replace_role(&mut draft, user, space, Some("control"));
                }
            }
            confirm = false;
            continue;
        }
        if let Some(ref mut search) = query {
            match key.code {
                KeyCode::Esc => query = None,
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(c) => search.push(c),
                KeyCode::Enter => {
                    match broker::request(socket, owner, "users", json!({"query":search})) {
                        Ok(result) => {
                            accounts = rows(&result, "accounts");
                            user_index = 0;
                        }
                        Err(error) => message = error.to_string(),
                    }
                    query = None;
                }
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => user_focus = !user_focus,
            KeyCode::Up | KeyCode::Char('k') => {
                if user_focus {
                    user_index = user_index.saturating_sub(1)
                } else {
                    space_index = space_index.saturating_sub(1)
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if user_focus {
                    user_index = (user_index + 1).min(accounts.len().saturating_sub(1))
                } else {
                    space_index = (space_index + 1).min(spaces.len().saturating_sub(1))
                }
            }
            KeyCode::Char('/') => query = Some(String::new()),
            KeyCode::Char('d') => confirm_disable = true,
            KeyCode::Char('r') => {
                if let Some(user) = accounts.get(user_index) {
                    draft.retain(|grant| grant["uid"] != user["uid"]);
                    message =
                        "All grants for this user removed from the draft. Press s to save.".into();
                }
            }
            KeyCode::Char(' ') if !user_focus => {
                if let (Some(user), Some(space)) =
                    (accounts.get(user_index), spaces.get(space_index))
                {
                    if user["uid"].as_u64() == Some(u64::from(owner)) {
                        message = "The session owner always has full access.".into();
                        continue;
                    }
                    let role = draft
                        .iter()
                        .find(|grant| {
                            grant["uid"] == user["uid"] && grant["workspace_id"] == space["id"]
                        })
                        .map(|grant| text(grant, "role"));
                    match role.as_deref() {
                        None => replace_role(&mut draft, user, space, Some("view")),
                        Some("view") => confirm = true,
                        _ => replace_role(&mut draft, user, space, None),
                    }
                }
            }
            KeyCode::Char('s') => {
                match broker::request(
                    socket,
                    owner,
                    "grants.set",
                    json!({"expected_revision":revision,"grants":draft,"acknowledge_owner_execution":acknowledged}),
                ) {
                    Ok(_) => break,
                    Err(error) => {
                        message = format!("Save failed: {error}. Cancel and reopen to refresh.")
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn replace_role(grants: &mut Vec<Value>, user: &Value, space: &Value, role: Option<&str>) {
    grants.retain(|grant| grant["uid"] != user["uid"] || grant["workspace_id"] != space["id"]);
    if let Some(role) = role {
        grants.push(json!({"uid":user["uid"],"account_name":user["name"],"workspace_id":space["id"],"role":role}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changing_one_grant_preserves_other_users_and_spaces() {
        let user = json!({"uid":1001,"name":"alice"});
        let space = json!({"id":"w1"});
        let mut grants =
            vec![json!({"uid":1002,"account_name":"bob","workspace_id":"w2","role":"view"})];
        replace_role(&mut grants, &user, &space, Some("view"));
        replace_role(&mut grants, &user, &space, Some("control"));
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[1]["role"], "control");
        replace_role(&mut grants, &user, &space, None);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["account_name"], "bob");
    }
    #[test]
    fn shared_projection_does_not_invent_control_for_viewers() {
        let state = json!({"workspaces":[{"id":"w1","label":"A","role":"view","tabs":[{"id":"t1","label":"Main","panes":[{"id":"p1","label":"shell"}]}]}]});
        let list = panes(&state);
        assert_eq!(list.len(), 1);
        assert!(!list[0].control);
    }
}
