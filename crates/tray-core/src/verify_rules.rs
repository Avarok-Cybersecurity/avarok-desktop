// SPDX-License-Identifier: MIT OR Apache-2.0
//! The field rules of a signed tab manifest. A signature proves who wrote a manifest, not that
//! it is sane, so every field is still checked: a pinned publisher's mistake must not become a
//! path outside the install roots or a panel off loopback.

use crate::manifest::{self, ActionSection, AgentSection, PanelSection, ReadySection, TabManifest};
use crate::model::{Action, AgentSpec, Launch, PanelSpec, PanelToken, ReadyProbe, Tab, TabId};
use crate::verify::{Platform, Refusal};
use crate::verify_paths;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const MAX_ARG_CHARS: usize = 1024;
const MAX_FRAGMENT_CHARS: usize = 256;
const MAX_MODULE_CHARS: usize = 64;
const LOWEST_AGENT_PORT: u16 = 1024;
const MAX_URL_CHARS: usize = 1024;

pub(crate) fn tab(m: &TabManifest, file_name: &str, platform: &Platform) -> Result<Tab, Refusal> {
    let id = TabId::parse(&m.id).ok_or_else(|| Refusal::BadId(m.id.clone()))?;
    let expected = id.manifest_file_name();
    if file_name != expected {
        return Err(Refusal::FileNameMismatch {
            file: file_name.to_owned(),
            expected,
        });
    }
    let program = verify_paths::program(&m.app, platform)?;
    let agent = agent(&m.agent, program)?;
    let ReadyProbe::Tcp { port } = agent.ready;
    Ok(Tab {
        title: title(&m.title)?,
        icon: icon(&m.icon_template_png)?,
        panel: panel(&m.panel, port)?,
        actions: actions(&m.actions)?,
        agent,
        id,
    })
}

fn title(text: &str) -> Result<String, Refusal> {
    let chars = text.chars().count();
    if chars == 0 || chars > manifest::MAX_TITLE_CHARS || text.chars().any(char::is_control) {
        return Err(Refusal::BadField(format!(
            "the title {text:?} must be 1 to {} printable characters",
            manifest::MAX_TITLE_CHARS
        )));
    }
    Ok(text.to_owned())
}

fn icon(b64: &str) -> Result<Vec<u8>, Refusal> {
    // A base64 string longer than this cannot decode to an allowed icon; refuse before decoding.
    let encoded_max = manifest::MAX_ICON_BYTES.div_ceil(3) * 4;
    if b64.len() > encoded_max {
        return Err(oversize_icon(b64.len() / 4 * 3));
    }
    let png = STANDARD
        .decode(b64)
        .map_err(|e| Refusal::BadField(format!("the icon is not base64: {e}")))?;
    if png.len() > manifest::MAX_ICON_BYTES {
        return Err(oversize_icon(png.len()));
    }
    if !png.starts_with(PNG_MAGIC) {
        return Err(Refusal::BadField("the icon is not a PNG".to_owned()));
    }
    Ok(png)
}

fn oversize_icon(len: usize) -> Refusal {
    Refusal::Oversize {
        what: "icon",
        len: u64::try_from(len).unwrap_or(u64::MAX),
        max: u64::try_from(manifest::MAX_ICON_BYTES).unwrap_or(u64::MAX),
    }
}

fn agent(a: &AgentSection, program: crate::model::Program) -> Result<AgentSpec, Refusal> {
    if a.argv.len() > manifest::MAX_ARGS
        || a.argv
            .iter()
            .any(|arg| arg.len() > MAX_ARG_CHARS || arg.contains('\0'))
    {
        return Err(Refusal::BadField(format!(
            "the agent takes at most {} arguments of {MAX_ARG_CHARS} bytes, without NUL",
            manifest::MAX_ARGS
        )));
    }
    if a.crash_cap == 0 || a.crash_cap > manifest::MAX_CRASH_CAP {
        return Err(Refusal::BadField(format!(
            "crash_cap {} is not between 1 and {}",
            a.crash_cap,
            manifest::MAX_CRASH_CAP
        )));
    }
    let ReadySection::Tcp { port } = a.ready;
    if port < LOWEST_AGENT_PORT {
        return Err(Refusal::BadField(format!(
            "the agent port {port} is below {LOWEST_AGENT_PORT}"
        )));
    }
    Ok(AgentSpec {
        program,
        argv: a.argv.clone(),
        ready: ReadyProbe::Tcp { port },
        crash_cap: a.crash_cap,
    })
}

/// A web panel only ever loads from `http://127.0.0.1:<the agent's own port>/`.
fn panel(p: &PanelSection, agent_port: u16) -> Result<PanelSpec, Refusal> {
    match p {
        PanelSection::Web { url, token } => {
            let origin = format!("http://127.0.0.1:{agent_port}");
            let path = (url.len() <= MAX_URL_CHARS)
                .then_some(url.as_str())
                .and_then(|url| url.strip_prefix(&origin))
                .filter(|path| path.starts_with('/'))
                .filter(|path| {
                    path.bytes()
                        .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#')
                })
                .ok_or_else(|| Refusal::NotLoopback(url.clone()))?;
            if token != "stdout-handshake" {
                return Err(Refusal::BadField(format!(
                    "panel token {token:?} is not known"
                )));
            }
            Ok(PanelSpec::Web {
                port: agent_port,
                path: path.to_owned(),
                token: PanelToken::StdoutHandshake,
            })
        }
        PanelSection::Native { macos_module } => {
            let ok = macos_module.len() <= MAX_MODULE_CHARS
                && macos_module
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && macos_module
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                return Err(Refusal::BadField(format!(
                    "{macos_module:?} is not a Swift module name"
                )));
            }
            Ok(PanelSpec::Native {
                macos_module: macos_module.clone(),
            })
        }
    }
}

fn actions(list: &[ActionSection]) -> Result<Vec<Action>, Refusal> {
    if list.len() > manifest::MAX_ACTIONS {
        return Err(Refusal::BadField(format!(
            "{} actions, more than the {} allowed",
            list.len(),
            manifest::MAX_ACTIONS
        )));
    }
    let mut out: Vec<Action> = Vec::with_capacity(list.len());
    for a in list {
        let id_ok = !a.id.is_empty()
            && a.id.len() <= MAX_MODULE_CHARS
            && a.id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok || out.iter().any(|seen| seen.id == a.id) {
            return Err(Refusal::BadField(format!(
                "action id {:?} is invalid or repeated",
                a.id
            )));
        }
        if let Some(fragment) = &a.launch.url_fragment {
            let ok = fragment.starts_with('#')
                && fragment.len() <= MAX_FRAGMENT_CHARS
                && fragment.bytes().all(|b| b.is_ascii_graphic());
            if !ok {
                return Err(Refusal::BadField(format!(
                    "{fragment:?} is not a URL fragment"
                )));
            }
        }
        out.push(Action {
            id: a.id.clone(),
            title: title(&a.title)?,
            launch: Launch {
                macos_open_bundle: a.launch.macos_open_bundle,
                url_fragment: a.launch.url_fragment.clone(),
            },
        });
    }
    Ok(out)
}
