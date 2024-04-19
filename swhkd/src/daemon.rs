use crate::config::Value;
use clap::{arg, Command};
use evdev::{AttributeSet, Device, InputEventKind, Key};
use nix::{
    sys::stat::{umask, Mode},
    unistd::{Group, Uid},
};
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    fs,
    fs::{OpenOptions, Permissions},
    io::prelude::*,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{exit, id, Stdio},
};
use sysinfo::{ProcessExt, System, SystemExt};
use tokio::select;
use tokio::time::{sleep, Instant};
use tokio::{sync::mpsc, time::Duration};
use tokio_stream::{StreamExt, StreamMap};
use tokio_udev::{AsyncMonitorSocket, EventType, MonitorBuilder};

mod config;
mod environ;
mod perms;
mod uinput;

#[cfg(test)]
mod tests;

struct KeyboardState {
    state_modifiers: HashSet<config::Modifier>,
    state_keysyms: AttributeSet<evdev::Key>,
}

impl KeyboardState {
    fn new() -> KeyboardState {
        KeyboardState { state_modifiers: HashSet::new(), state_keysyms: AttributeSet::new() }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = set_command_line_args().get_matches();
    env::set_var("RUST_LOG", "swhkd=warn");

    if args.is_present("debug") {
        env::set_var("RUST_LOG", "swhkd=trace");
    }

    env_logger::init();
    log::trace!("Logger initialized.");

    let user_uid = match get_uid() {
        Ok(uid) => uid,
        Err(e) => {
            log::error!("Error: {}", e);
            exit(1);
        }
    };

    let env = environ::Env::load(&user_uid);
    println!("{}, {:#?}", user_uid, env);
    log::trace!("Environment Aquired");
    //UNDO perms::raise_privileges();

    exit(0);

    setup_swhkd(user_uid, env.xdg_runtime_dir.clone().to_string_lossy().to_string());

    let (sender, mut receiver) = mpsc::channel::<String>(100);

    tokio::spawn(async move {
        perms::drop_privileges(user_uid);
        loop {
            match receiver.try_recv() {
                Ok(cmd) => {
                    log::info!("Received command: {}", cmd);
                    run_system_command(&cmd, Path::new("/tmp/swhkd.log"));
                }
                Err(_) => {
                    // log::trace!("No command received.");
                }
            }
        }
    });

    let load_config = || {
        // Drop privileges to the invoking user.
        perms::drop_privileges(user_uid);

        let config_file_path: PathBuf = if args.is_present("config") {
            Path::new(args.value_of("config").unwrap()).to_path_buf()
        } else {
            env.fetch_xdg_config_path()
        };

        log::debug!("Using config file path: {:#?}", config_file_path);

        match config::load(&config_file_path) {
            Err(e) => {
                log::error!("Config Error: {}", e);
                exit(1)
            }
            Ok(out) => {
                // Escalate back to the root user after reading the config file.
                perms::raise_privileges();
                out
            }
        }
    };

    let mut modes = load_config();
    let mut mode_stack: Vec<usize> = vec![0];

    macro_rules! send_command {
        ($hotkey: expr, $socket_path: expr) => {
            log::info!("Hotkey pressed: {:#?}", $hotkey);
            let command = $hotkey.command;
            let mut commands_to_send = String::new();
            if modes[mode_stack[mode_stack.len() - 1]].options.oneoff {
                mode_stack.pop();
            }
            if command.contains('@') {
                let commands = command.split("&&").map(|s| s.trim()).collect::<Vec<_>>();
                for cmd in commands {
                    match cmd.split(' ').next().unwrap() {
                        config::MODE_ENTER_STATEMENT => {
                            let enter_mode = cmd.split(' ').nth(1).unwrap();
                            for (i, mode) in modes.iter().enumerate() {
                                if mode.name == enter_mode {
                                    mode_stack.push(i);
                                    break;
                                }
                            }
                            log::info!(
                                "Entering mode: {}",
                                modes[mode_stack[mode_stack.len() - 1]].name
                            );
                        }
                        config::MODE_ESCAPE_STATEMENT => {
                            mode_stack.pop();
                        }
                        _ => commands_to_send.push_str(format!("{cmd} &&").as_str()),
                    }
                }
            } else {
                commands_to_send = command;
            }
            if commands_to_send.ends_with(" &&") {
                commands_to_send = commands_to_send.strip_suffix(" &&").unwrap().to_string();
            }
            if let Err(e) = sender.send(commands_to_send).await {
                log::error!("Error sending data to execution thread");
                log::error!("Err: {:#?}", e)
            }
        };
    }

    let arg_devices: Vec<&str> = args.values_of("device").unwrap_or_default().collect();

    let keyboard_devices: Vec<_> = {
        if arg_devices.is_empty() {
            log::trace!("Attempting to find all keyboard file descriptors.");
            evdev::enumerate().filter(|(_, dev)| check_device_is_keyboard(dev)).collect()
        } else {
            evdev::enumerate()
                .filter(|(_, dev)| arg_devices.contains(&dev.name().unwrap_or("")))
                .collect()
        }
    };

    if keyboard_devices.is_empty() {
        log::error!("No valid keyboard device was detected!");
        exit(1);
    }

    log::debug!("{} Keyboard device(s) detected.", keyboard_devices.len());

    // Apparently, having a single uinput device with keys, relative axes and switches
    // prevents some libraries to listen to these events. The easy fix is to have separate
    // virtual devices, one for keys and relative axes (`uinput_device`) and another one
    // just for switches (`uinput_switches_device`).
    let mut uinput_device = match uinput::create_uinput_device() {
        Ok(dev) => dev,
        Err(e) => {
            log::error!("Err: {:#?}", e);
            exit(1);
        }
    };

    let mut uinput_switches_device = match uinput::create_uinput_switches_device() {
        Ok(dev) => dev,
        Err(e) => {
            log::error!("Err: {:#?}", e);
            exit(1);
        }
    };

    let mut udev =
        AsyncMonitorSocket::new(MonitorBuilder::new()?.match_subsystem("input")?.listen()?)?;

    let modifiers_map: HashMap<Key, config::Modifier> = HashMap::from([
        (Key::KEY_LEFTMETA, config::Modifier::Super),
        (Key::KEY_RIGHTMETA, config::Modifier::Super),
        (Key::KEY_LEFTALT, config::Modifier::Alt),
        (Key::KEY_RIGHTALT, config::Modifier::Altgr),
        (Key::KEY_LEFTCTRL, config::Modifier::Control),
        (Key::KEY_RIGHTCTRL, config::Modifier::Control),
        (Key::KEY_LEFTSHIFT, config::Modifier::Shift),
        (Key::KEY_RIGHTSHIFT, config::Modifier::Shift),
    ]);

    let repeat_cooldown_duration: u64 = if args.is_present("cooldown") {
        args.value_of("cooldown").unwrap().parse::<u64>().unwrap()
    } else {
        250
    };

    let mut signals = Signals::new([
        SIGUSR1, SIGUSR2, SIGHUP, SIGABRT, SIGBUS, SIGCHLD, SIGCONT, SIGINT, SIGPIPE, SIGQUIT,
        SIGSYS, SIGTERM, SIGTRAP, SIGTSTP, SIGVTALRM, SIGXCPU, SIGXFSZ,
    ])?;

    let mut execution_is_paused = false;
    let mut last_hotkey: Option<config::Hotkey> = None;
    let mut pending_release: bool = false;
    let mut keyboard_states = HashMap::new();
    let mut keyboard_stream_map = StreamMap::new();

    for (path, mut device) in keyboard_devices.into_iter() {
        let _ = device.grab();
        let path = match path.to_str() {
            Some(p) => p,
            None => {
                continue;
            }
        };
        keyboard_states.insert(path.to_string(), KeyboardState::new());
        keyboard_stream_map.insert(path.to_string(), device.into_event_stream()?);
    }

    // The initial sleep duration is never read because last_hotkey is initialized to None
    let hotkey_repeat_timer = sleep(Duration::from_millis(0));
    tokio::pin!(hotkey_repeat_timer);

    // The socket we're sending the commands to.
    let _socket_file_path = env.fetch_xdg_runtime_socket_path();
    loop {
        select! {
            _ = &mut hotkey_repeat_timer, if &last_hotkey.is_some() => {
                let hotkey = last_hotkey.clone().unwrap();
                if hotkey.keybinding.on_release {
                    continue;
                }
                send_command!(hotkey.clone(), &socket_file_path);
                hotkey_repeat_timer.as_mut().reset(Instant::now() + Duration::from_millis(repeat_cooldown_duration));
            }

            Some(signal) = signals.next() => {
                match signal {
                    SIGUSR1 => {
                        execution_is_paused = true;
                        for mut device in evdev::enumerate().map(|(_, device)| device).filter(check_device_is_keyboard) {
                            let _ = device.ungrab();
                        }
                    }

                    SIGUSR2 => {
                        execution_is_paused = false;
                        for mut device in evdev::enumerate().map(|(_, device)| device).filter(check_device_is_keyboard) {
                            let _ = device.grab();
                        }
                    }

                    SIGHUP => {
                        modes = load_config();
                        mode_stack = vec![0];
                    }

                    SIGINT => {
                        for mut device in evdev::enumerate().map(|(_, device)| device).filter(check_device_is_keyboard) {
                            let _ = device.ungrab();
                        }
                        log::warn!("Received SIGINT signal, exiting...");
                        exit(1);
                    }

                    _ => {
                        for mut device in evdev::enumerate().map(|(_, device)| device).filter(check_device_is_keyboard) {
                            let _ = device.ungrab();
                        }

                        log::warn!("Received signal: {:#?}", signal);
                        log::warn!("Exiting...");
                        exit(1);
                    }
                }
            }

            Some(Ok(event)) = udev.next() => {
                if !event.is_initialized() {
                    log::warn!("Received udev event with uninitialized device.");
                }

                let node = match event.devnode() {
                    None => { continue; },
                    Some(node) => {
                        match node.to_str() {
                            None => { continue; },
                            Some(node) => node,
                        }
                    },
                };

                match event.event_type() {
                    EventType::Add => {
                        let mut device = match Device::open(node) {
                            Err(e) => {
                                log::error!("Could not open evdev device at {}: {}", node, e);
                                continue;
                            },
                            Ok(device) => device
                        };
                        let name = device.name().unwrap_or("[unknown]");
                        if arg_devices.contains(&name) || check_device_is_keyboard(&device) {
                            log::info!("Device '{}' at '{}' added.", name, node);
                            let _ = device.grab();
                            keyboard_states.insert(node.to_string(), KeyboardState::new());
                            keyboard_stream_map.insert(node.to_string(), device.into_event_stream()?);
                        }
                    }
                    EventType::Remove => {
                        if keyboard_stream_map.contains_key(node) {
                            keyboard_states.remove(node);
                            let stream = keyboard_stream_map.remove(node).expect("device not in stream_map");
                            let name = stream.device().name().unwrap_or("[unknown]");
                            log::info!("Device '{}' at '{}' removed", name, node);
                        }
                    }
                    _ => {
                        log::trace!("Ignored udev event of type: {:?}", event.event_type());
                    }
                }
            }

            Some((node, Ok(event))) = keyboard_stream_map.next() => {
                let keyboard_state = &mut keyboard_states.get_mut(&node).expect("device not in states map");

                let key = match event.kind() {
                    InputEventKind::Key(keycode) => keycode,
                    InputEventKind::Switch(_) => {
                        uinput_switches_device.emit(&[event]).unwrap();
                        continue
                    }
                    _ => {
                        uinput_device.emit(&[event]).unwrap();
                        continue
                    }
                };

                match event.value() {
                    // Key press
                    1 => {
                        if let Some(modifier) = modifiers_map.get(&key) {
                            keyboard_state.state_modifiers.insert(*modifier);
                        } else {
                            keyboard_state.state_keysyms.insert(key);
                        }
                    }

                    // Key release
                    0 => {
                        if last_hotkey.is_some() && pending_release {
                            pending_release = false;
                            send_command!(last_hotkey.clone().unwrap(), &socket_file_path);
                            last_hotkey = None;
                        }
                        if let Some(modifier) = modifiers_map.get(&key) {
                            if let Some(hotkey) = &last_hotkey {
                                if hotkey.modifiers().contains(modifier) {
                                    last_hotkey = None;
                                }
                            }
                            keyboard_state.state_modifiers.remove(modifier);
                        } else if keyboard_state.state_keysyms.contains(key) {
                            if let Some(hotkey) = &last_hotkey {
                                if key == hotkey.keysym() {
                                    last_hotkey = None;
                                }
                            }
                            keyboard_state.state_keysyms.remove(key);
                        }
                    }

                    _ => {}
                }

                let possible_hotkeys: Vec<&config::Hotkey> = modes[mode_stack[mode_stack.len() - 1]].hotkeys.iter()
                    .filter(|hotkey| hotkey.modifiers().len() == keyboard_state.state_modifiers.len())
                    .collect();

                let event_in_hotkeys = modes[mode_stack[mode_stack.len() - 1]].hotkeys.iter().any(|hotkey| {
                    hotkey.keysym().code() == event.code() &&
                        (!keyboard_state.state_modifiers.is_empty() && hotkey.modifiers().contains(&config::Modifier::Any) || keyboard_state.state_modifiers
                        .iter()
                        .all(|x| hotkey.modifiers().contains(x)) &&
                    keyboard_state.state_modifiers.len() == hotkey.modifiers().len())
                    && !hotkey.is_send()
                        });

                // Only emit event to virtual device when swallow option is off
                if !modes[mode_stack[mode_stack.len()-1]].options.swallow
                // Don't emit event to virtual device if it's from a valid hotkey
                && !event_in_hotkeys {
                    uinput_device.emit(&[event]).unwrap();
                }

                if execution_is_paused || possible_hotkeys.is_empty() || last_hotkey.is_some() {
                    continue;
                }

                log::debug!("state_modifiers: {:#?}", keyboard_state.state_modifiers);
                log::debug!("state_keysyms: {:#?}", keyboard_state.state_keysyms);
                log::debug!("hotkey: {:#?}", possible_hotkeys);

                for hotkey in possible_hotkeys {
                    // this should check if state_modifiers and hotkey.modifiers have the same elements
                    if (!keyboard_state.state_modifiers.is_empty() && hotkey.modifiers().contains(&config::Modifier::Any) || keyboard_state.state_modifiers.iter().all(|x| hotkey.modifiers().contains(x))
                        && keyboard_state.state_modifiers.len() == hotkey.modifiers().len())
                        && keyboard_state.state_keysyms.contains(hotkey.keysym())
                    {
                        last_hotkey = Some(hotkey.clone());
                        if pending_release { break; }
                        if hotkey.is_on_release() {
                            pending_release = true;
                            break;
                        }
                        send_command!(hotkey.clone(), &socket_file_path);
                        hotkey_repeat_timer.as_mut().reset(Instant::now() + Duration::from_millis(repeat_cooldown_duration));
                        continue;
                    }
                }
            }
        }
    }
}

fn _socket_write(command: &str, socket_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(command.as_bytes())?;
    Ok(())
}

pub fn check_input_group() -> Result<(), Box<dyn Error>> {
    if !Uid::current().is_root() {
        let groups = nix::unistd::getgroups();
        for groups in groups.iter() {
            for group in groups {
                let group = Group::from_gid(*group);
                if group.unwrap().unwrap().name == "input" {
                    log::error!("Note: INVOKING USER IS IN INPUT GROUP!!!!");
                    log::error!("THIS IS A HUGE SECURITY RISK!!!!");
                }
            }
        }
        Err("Invoking user is not in the input group!")?
    } else {
        log::warn!("Running swhkd as root!");
        Ok(())
    }
}

pub fn check_device_is_keyboard(device: &Device) -> bool {
    if device.supported_keys().map_or(false, |keys| keys.contains(Key::KEY_ENTER)) {
        if device.name() == Some("swhkd virtual output") {
            return false;
        }
        log::debug!("Keyboard: {}", device.name().unwrap(),);
        true
    } else {
        log::trace!("Other: {}", device.name().unwrap(),);
        false
    }
}

pub fn set_command_line_args() -> Command<'static> {
    let app = Command::new("swhkd")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Simple Wayland HotKey Daemon")
        .arg(
            arg!(-c --config <CONFIG_FILE_PATH>)
                .required(false)
                .takes_value(true)
                .help("Set a custom config file path."),
        )
        .arg(
            arg!(-C --cooldown <COOLDOWN_IN_MS>)
                .required(false)
                .takes_value(true)
                .help("Set a custom repeat cooldown duration. Default is 250ms."),
        )
        .arg(arg!(-d - -debug).required(false).help("Enable debug mode."))
        .arg(
            arg!(-D --device <DEVICE_NAME>)
                .required(false)
                .takes_value(true)
                .multiple_occurrences(true)
                .help(
                    "Specific keyboard devices to use. Seperate multiple devices with semicolon.",
                ),
        );
    app
}

pub fn setup_swhkd(invoking_uid: u32, runtime_path: String) {
    // Set a sane process umask.
    log::trace!("Setting process umask.");
    umask(Mode::S_IWGRP | Mode::S_IWOTH);

    // Get the runtime path and create it if needed.
    if !Path::new(&runtime_path).exists() {
        match fs::create_dir_all(Path::new(&runtime_path)) {
            Ok(_) => {
                log::debug!("Created runtime directory.");
                match fs::set_permissions(Path::new(&runtime_path), Permissions::from_mode(0o600)) {
                    Ok(_) => log::debug!("Set runtime directory to readonly."),
                    Err(e) => log::error!("Failed to set runtime directory to readonly: {}", e),
                }
            }
            Err(e) => log::error!("Failed to create runtime directory: {}", e),
        }
    }

    // Get the PID file path for instance tracking.
    let pidfile: String = format!("{}/swhkd_{}.pid", runtime_path, invoking_uid);
    if Path::new(&pidfile).exists() {
        log::trace!("Reading {} file and checking for running instances.", pidfile);
        let swhkd_pid = match fs::read_to_string(&pidfile) {
            Ok(swhkd_pid) => swhkd_pid,
            Err(e) => {
                log::error!("Unable to read {} to check all running instances", e);
                exit(1);
            }
        };
        log::debug!("Previous PID: {}", swhkd_pid);

        // Check if swhkd is already running!
        let mut sys = System::new_all();
        sys.refresh_all();
        for (pid, process) in sys.processes() {
            if pid.to_string() == swhkd_pid && process.exe() == env::current_exe().unwrap() {
                log::error!("Swhkd is already running!");
                log::error!("pid of existing swhkd process: {}", pid.to_string());
                log::error!("To close the existing swhkd process, run `sudo killall swhkd`");
                exit(1);
            }
        }
    }

    // Write to the pid file.
    match fs::write(&pidfile, id().to_string()) {
        Ok(_) => {}
        Err(e) => {
            log::error!("Unable to write to {}: {}", pidfile, e);
            exit(1);
        }
    }

    if check_input_group().is_err() {
        log::error!("Sudo permissions are required to run swhkd!");
        exit(1);
    }
}

/// Run a system command and log the output to a file.
fn run_system_command(command: &str, log_path: &Path) {
    if let Err(e) = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(match OpenOptions::new().append(true).create(true).open(log_path) {
            Ok(file) => file,
            Err(e) => {
                _ = std::process::Command::new("notify-send").arg(format!("ERROR {}", e)).spawn();
                exit(1);
            }
        })
        .stderr(match OpenOptions::new().append(true).create(true).open(log_path) {
            Ok(file) => file,
            Err(e) => {
                _ = std::process::Command::new("notify-send").arg(format!("ERROR {}", e)).spawn();
                exit(1);
            }
        })
        .spawn()
    {
        log::error!("Failed to execute {}", command);
        log::error!("Error: {}", e);
    }
}

fn parse_uid_from_line(line: &str) -> u32 {
    line.split(':').nth(2).unwrap().parse::<u32>().unwrap()
}

fn get_uid() -> Result<u32, Box<dyn Error>> {
    let pwd_content = fs::read_to_string("/etc/passwd").expect("Unable to read /etc/passwd");

    let pwd_lines = pwd_content.lines().collect::<Vec<_>>();
    match pwd_lines.iter().find(|line| {
        !line.contains("nologin") && line.contains("/bin") && parse_uid_from_line(line) >= 1000
    }) {
        Some(line) => Ok(parse_uid_from_line(line)),
        None => Err("Unable to find user in /etc/passwd")?,
    }
}
