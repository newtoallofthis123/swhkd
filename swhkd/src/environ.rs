use std::collections::HashMap;
use std::hash::Hash;
use std::{
    env::VarError,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct Env {
    pub xdg_config_home: PathBuf,
    pub xdg_runtime_socket: PathBuf,
    pub xdg_runtime_dir: PathBuf,
    external_env: HashMap<String, String>,
}

#[derive(Debug)]
pub enum EnvError {
    XdgConfigNotFound,
    XdgRuntimeNotFound,
    PathNotFound,
    GenericError(String),
}

impl Env {
    pub fn new() -> Self {
        Self {
            xdg_config_home: PathBuf::new(),
            xdg_runtime_socket: PathBuf::new(),
            xdg_runtime_dir: PathBuf::new(),
            external_env: HashMap::new(),
        }
    }

    pub fn construct(&mut self, user_id: u32) {
        let xdg_config_home = match self.get_env("XDG_CONFIG_HOME") {
            Ok(val) => validate_path(&PathBuf::from(val)).unwrap_or_else(|e| match e {
                EnvError::PathNotFound => {
                    log::warn!("XDG_CONFIG_HOME does not exist, using hardcoded /etc");
                    PathBuf::from("/etc")
                }
                _ => {
                    eprintln!("Failed to get XDG_CONFIG_HOME: {:?}", e);
                    std::process::exit(1);
                }
            }),
            Err(e) => match e {
                EnvError::XdgConfigNotFound => {
                    log::warn!("XDG_CONFIG_HOME not found, using hardcoded /etc");
                    PathBuf::from("/etc")
                }
                _ => {
                    eprintln!("Failed to get XDG_CONFIG_HOME: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        let xdg_runtime_socket = match self.get_env("XDG_RUNTIME_DIR") {
            Ok(val) => match validate_path(&PathBuf::from(val).join("swhkd.sock")) {
                Ok(val) => val,
                Err(e) => match e {
                    EnvError::PathNotFound => {
                        log::warn!("XDG_RUNTIME_DIR does not exist, using hardcoded /run/user");
                        PathBuf::from(format!("/run/user/{}/", user_id))
                    }
                    _ => {
                        eprintln!("Failed to get XDG_RUNTIME_DIR: {:?}", e);
                        std::process::exit(1);
                    }
                },
            },
            Err(e) => match e {
                EnvError::XdgRuntimeNotFound => {
                    log::warn!("XDG_RUNTIME_DIR not found, using hardcoded /run/user");
                    PathBuf::from(format!("/run/user/{}/", user_id))
                }
                _ => {
                    eprintln!("Failed to get XDG_RUNTIME_DIR: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        let xdg_runtime_dir = match self.get_env("XDG_RUNTIME_DIR") {
            Ok(val) => PathBuf::from(val),
            Err(e) => match e {
                EnvError::XdgRuntimeNotFound => {
                    log::warn!("XDG_RUNTIME_DIR not found, using hardcoded /run/user");
                    PathBuf::from(format!("/run/user/{}/", user_id))
                }
                _ => {
                    eprintln!("Failed to get XDG_RUNTIME_DIR: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        self.xdg_config_home = xdg_config_home;
        self.xdg_runtime_socket = xdg_runtime_socket;
        self.xdg_runtime_dir = xdg_runtime_dir;
    }

    fn get_env(&self, name: &str) -> Result<String, EnvError> {
        if let Some(val) = self.external_env.get(name) {
            return Ok(val.to_string());
        }
        match std::env::var(name) {
            Ok(val) => Ok(val),
            Err(e) => match e {
                VarError::NotPresent => match name {
                    "XDG_CONFIG_HOME" => Err(EnvError::XdgConfigNotFound),
                    "XDG_RUNTIME_DIR" => Err(EnvError::XdgRuntimeNotFound),
                    _ => Err(EnvError::GenericError(e.to_string())),
                },
                VarError::NotUnicode(_) => {
                    Err(EnvError::GenericError("Not a valid unicode".to_string()))
                }
            },
        }
    }

    pub fn set_external_env(&mut self, env: HashMap<String, String>) {
        self.external_env = env;
    }

    pub fn fetch_xdg_config_path(&self) -> PathBuf {
        PathBuf::from(&self.xdg_config_home).join("swhkd/swhkdrc")
    }

    pub fn fetch_xdg_runtime_socket_path(&self) -> PathBuf {
        PathBuf::from(&self.xdg_runtime_dir).join("swhkd.sock")
    }
}

fn validate_path(path: &Path) -> Result<PathBuf, EnvError> {
    if path.exists() {
        Ok(path.to_path_buf())
    } else {
        Err(EnvError::PathNotFound)
    }
}
