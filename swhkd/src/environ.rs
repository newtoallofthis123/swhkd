use std::{
    env::VarError,
    path::{Path, PathBuf},
};

pub struct Env {
    pub exec_id: u32,
    pub xdg_config_home: PathBuf,
    pub home: PathBuf,
    pub xdg_runtime_socket: PathBuf,
    pub xdg_data_home: PathBuf,
    pub xdg_runtime_dir: PathBuf,
    pub user_runtime_dir: PathBuf,
}

#[derive(Debug)]
pub enum EnvError {
    PkexecNotFound,
    XdgConfigNotFound,
    XdgRuntimeNotFound,
    XdgDataHomeNotFound,
    PathNotFound,
    GenericError(String),
}

impl Env {
    pub fn construct() -> Self {
        // let pkexec_id = match Self::get_env("PKEXEC_UID") {
        //     Ok(val) => match val.parse::<u32>() {
        //         Ok(val) => val,
        //         Err(_) => {
        //             log::error!("Failed to launch swhkd!!!");
        //             log::error!("Make sure to launch the binary with pkexec.");
        //             std::process::exit(1);
        //         }
        //     },
        //     Err(_) => {
        //         log::error!("Failed to launch swhkd!!!");
        //         log::error!("Make sure to launch the binary with pkexec.");
        //         std::process::exit(1);
        //     }
        // };

        let exec_id = nix::unistd::Uid::current().as_raw();

        let home = match Self::get_env("HOME") {
            Ok(val) => PathBuf::from(val),
            Err(_) => {
                eprintln!("HOME Variable is not set/found, cannot fall back on hardcoded path for XDG_DATA_HOME.");
                std::process::exit(1);
            }
        };

        let xdg_config_home = match Self::get_env("XDG_CONFIG_HOME") {
            Ok(val) => match validate_path(&PathBuf::from(val)) {
                Ok(val) => val,
                Err(e) => match e {
                    EnvError::PathNotFound => {
                        log::warn!("XDG_CONFIG_HOME does not exist, using hardcoded /etc");
                        PathBuf::from("/etc")
                    }
                    _ => {
                        eprintln!("Failed to get XDG_CONFIG_HOME: {:?}", e);
                        std::process::exit(1);
                    }
                },
            },
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

        let xdg_runtime_socket = match Self::get_env("XDG_RUNTIME_DIR") {
            Ok(val) => match validate_path(&PathBuf::from(val).join("swhkd.sock")) {
                Ok(val) => val,
                Err(e) => match e {
                    EnvError::PathNotFound => {
                        log::warn!("XDG_RUNTIME_DIR does not exist, using hardcoded /run/user");
                        PathBuf::from(format!("/run/user/{}", exec_id))
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
                    PathBuf::from(format!("/run/user/{}", exec_id))
                }
                _ => {
                    eprintln!("Failed to get XDG_RUNTIME_DIR: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        let xdg_runtime_dir = match Self::get_env("XDG_RUNTIME_DIR") {
            Ok(val) => PathBuf::from(val),
            Err(e) => match e {
                EnvError::XdgRuntimeNotFound => {
                    log::warn!("XDG_RUNTIME_DIR not found, using hardcoded /run/swhkd");
                    PathBuf::from("/run/swhkd")
                }
                _ => {
                    eprintln!("Failed to get XDG_RUNTIME_DIR: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        let xdg_data_home = match Self::get_env("XDG_DATA_HOME") {
            Ok(val) => match validate_path(&PathBuf::from(val)) {
                Ok(val) => val,
                Err(e) => match e {
                    EnvError::PathNotFound => {
                        log::warn!("XDG_DATA_HOME does not exist, using hardcoded /usr/share");
                        home.join(".local/share")
                    }
                    _ => {
                        eprintln!("Failed to get XDG_DATA_HOME: {:?}", e);
                        std::process::exit(1);
                    }
                },
            },
            Err(e) => match e {
                EnvError::XdgDataHomeNotFound => {
                    log::warn!("XDG_DATA_HOME not found, using hardcoded /usr/share");
                    home.join(".local/share")
                }
                _ => {
                    eprintln!("Failed to get XDG_DATA_HOME: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        let user_runtime_dir = match Self::get_env("XDG_RUNTIME_DIR") {
            Ok(val) => PathBuf::from(val),
            Err(e) => match e {
                EnvError::XdgRuntimeNotFound => {
                    log::warn!("User runtime directory does not exist, using hardcoded /run/user");
                    PathBuf::from(format!("/run/user/{}", nix::unistd::Uid::current()))
                }
                _ => {
                    eprintln!("Failed to get user runtime directory: {:?}", e);
                    std::process::exit(1);
                }
            },
        };

        Self {
            exec_id,
            xdg_config_home,
            home,
            xdg_runtime_dir,
            xdg_runtime_socket,
            xdg_data_home,
            user_runtime_dir,
        }
    }

    fn get_env(name: &str) -> Result<String, EnvError> {
        match std::env::var(name) {
            Ok(val) => Ok(val),
            Err(e) => match e {
                VarError::NotPresent => match name {
                    "PKEXEC_UID" => Err(EnvError::PkexecNotFound),
                    "XDG_CONFIG_HOME" => Err(EnvError::XdgConfigNotFound),
                    "XDG_RUNTIME_DIR" => Err(EnvError::XdgRuntimeNotFound),
                    "XDG_DATA_HOME" => Err(EnvError::XdgDataHomeNotFound),
                    "HOME" => Err(EnvError::PathNotFound),
                    _ => Err(EnvError::GenericError(e.to_string())),
                },
                VarError::NotUnicode(_) => {
                    Err(EnvError::GenericError("Not a valid unicode".to_string()))
                }
            },
        }
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
