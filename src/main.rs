use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io;
use std::io::Write;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, Args, ArgAction};
use dialoguer::{theme::ColorfulTheme, Input, Password, Confirm, Select};
use indicatif::{ProgressBar, ProgressStyle};
use console::{style, Term};
use which::which;

#[derive(Parser, Debug)]
#[command(name = "ferruz")]
#[command(author = "Tristan Polandit")]
#[command(version = "1.0")]
#[command(about = "DayZ Server Manager in Docker", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Deploy a new DayZ server
    #[command(visible_alias = "d")]
    Deploy(DeployArgs),
    
    /// Start an existing DayZ server
    #[command(visible_alias = "s")]
    Start {
        /// Server name
        name: String,
    },
    
    /// Stop a running DayZ server
    #[command(visible_alias = "down")]
    Stop {
        /// Server name
        name: String,
    },
    
    /// Restart a running DayZ server
    #[command(visible_alias = "r")]
    Restart {
        /// Server name
        name: String,
    },
    
    /// List all DayZ servers
    #[command(visible_alias = "ls")]
    List {},
    
    /// Configure Steam credentials
    #[command(visible_alias = "cfg")]
    Config {},
    
    /// View or follow server logs
    #[command(visible_alias = "l")]
    Logs(LogsArgs),
    
    /// Execute a command on the server
    #[command(visible_alias = "exec")]
    Execute {
        /// Server name
        name: String,
        
        /// Command to execute
        command: Vec<String>,
    },
    
    /// Show server status
    #[command(visible_alias = "stat")]
    Status {
        /// Server name
        name: String,
    },
    
    /// Update the server
    #[command(visible_alias = "up")]
    Update {
        /// Server name
        name: String,
        
        /// Force validation of server files
        #[arg(short, long)]
        validate: bool,
    },
    
    /// Manage server mods
    #[command(visible_alias = "mod", subcommand)]
    Mods(ModsCommand),
    
    /// Access an interactive shell in the server container
    #[command(visible_alias = "sh")]
    Shell {
        /// Server name
        name: String,
    },
    
    /// Create a backup of server data
    #[command(visible_alias = "bkp")]
    Backup {
        /// Server name
        name: String,
        
        /// Backup destination directory
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Restore a backup
    #[command(visible_alias = "rest")]
    Restore {
        /// Server name
        name: String,
        
        /// Path to backup file
        path: String,
    },
}

#[derive(Args, Debug)]
struct DeployArgs {
    /// Server name
    #[arg(short, long)]
    name: Option<String>,
    
    /// Server port (default: 2302)
    #[arg(short, long)]
    port: Option<u16>,
    
    /// Max players (default: 60)
    #[arg(short = 'm', long)]
    max_players: Option<u16>,
    
    /// Custom server configuration file
    #[arg(short, long)]
    config: Option<String>,
    
    /// Use custom mods (comma separated workshop IDs)
    #[arg(long)]
    mods: Option<String>,
    
    /// Server password
    #[arg(long)]
    password: Option<String>,
    
    /// Admin password
    #[arg(short = 'a', long)]
    admin_password: Option<String>,
    
    /// Server location (map) - default: chernarusplus
    #[arg(short, long)]
    location: Option<String>,
    
    /// Interactive mode
    #[arg(short, long, default_value = "true")]
    interactive: bool,
}

#[derive(Args, Debug)]
struct LogsArgs {
    /// Server name
    name: String,
    
    /// Follow logs (continuous output)
    #[arg(short, long)]
    follow: bool,
    
    /// Number of lines to show
    #[arg(short, long, default_value = "100")]
    lines: usize,
}

#[derive(Subcommand, Debug)]
enum ModsCommand {
    /// List installed mods
    List {
        /// Server name
        name: String,
    },
    
    /// Add mods to server
    Add {
        /// Server name
        name: String,
        
        /// Workshop IDs of mods to add
        mods: String,
    },
    
    /// Remove mods from server
    Remove {
        /// Server name
        name: String,
        
        /// Workshop IDs of mods to remove
        mods: String,
    },
    
    /// Update all installed mods
    Update {
        /// Server name
        name: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ServerConfig {
    name: String,
    port: u16,
    max_players: u16,
    mods: Vec<String>,
    container_id: Option<String>,
    password: Option<String>,
    admin_password: String,
    location: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    steam_username: String,
    steam_password: String,
    servers: Vec<ServerConfig>,
    docker_compose_version: u8,  // 1 or 2
    last_backup_check: Option<DateTime<Utc>>,
}

impl Config {
    fn new() -> Self {
        Config {
            steam_username: String::new(),
            steam_password: String::new(),
            servers: Vec::new(),
            docker_compose_version: 2,  // Default to Docker Compose v2
            last_backup_check: None,
        }
    }

    fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Config::new());
        }
        
        let json = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&json)?;
        Ok(config)
    }
    
    fn encrypt_password(&mut self) {
        if self.steam_password.is_empty() {
            return;
        }
        
        // Basic encryption - not truly secure but better than plaintext
        // In a production app, use a proper keystore
        let mut hasher = Sha256::new();
        hasher.update("ferruz-dayz-server-manager-salt");
        let key = hasher.finalize();
        
        let password_bytes = self.steam_password.as_bytes();
        let mut encrypted = Vec::new();
        
        for (i, byte) in password_bytes.iter().enumerate() {
            encrypted.push(byte ^ key[i % key.len()]);
        }
        
        self.steam_password = general_purpose::STANDARD.encode(encrypted);
    }
    
    fn decrypt_password(&self) -> String {
        if self.steam_password.is_empty() {
            return String::new();
        }
        
        // Reverse the encryption
        let encrypted = general_purpose::STANDARD.decode(&self.steam_password).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update("ferruz-dayz-server-manager-salt");
        let key = hasher.finalize();
        
        let mut password_bytes = Vec::new();
        for (i, byte) in encrypted.iter().enumerate() {
            password_bytes.push(byte ^ key[i % key.len()]);
        }
        
        String::from_utf8(password_bytes).unwrap_or_default()
    }
}

fn get_ferruz_dir() -> PathBuf {
    let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("ferruz");
    if let Err(_) = fs::create_dir_all(&path) {
        eprintln!("Failed to create ferruz data directory");
    }
    path
}

fn get_config_path() -> PathBuf {
    let mut path = get_ferruz_dir();
    path.push("config.json");
    path
}

fn get_servers_dir() -> PathBuf {
    let mut path = get_ferruz_dir();
    path.push("servers");
    fs::create_dir_all(&path).unwrap_or_else(|_| {
        eprintln!("Failed to create servers directory");
    });
    path
}

fn get_docker_compose_path(server_name: &str) -> PathBuf {
    let mut path = get_servers_dir();
    path.push(format!("{}.yml", server_name));
    path
}

fn get_data_dir(server_name: &str) -> PathBuf {
    let mut path = get_servers_dir();
    path.push("data");
    path.push(format!("dayz-server-{}", server_name));
    fs::create_dir_all(&path).unwrap_or_else(|_| {
        eprintln!("Failed to create server data directory");
    });
    path
}

fn docker_compose_cmd(config: &Config) -> Vec<String> {
    if config.docker_compose_version == 1 {
        vec!["docker-compose".to_string()]
    } else {
        vec!["docker".to_string(), "compose".to_string()]
    }
}

fn detect_docker_compose_version() -> u8 {
    // Check if docker compose (v2) is available
    if let Ok(_) = Command::new("docker").arg("compose").arg("version").output() {
        return 2;
    }
    
    // Check if docker-compose (v1) is available
    if let Ok(_) = Command::new("docker-compose").arg("--version").output() {
        return 1;
    }
    
    // Default to v2 if we can't determine
    2
}

fn configure_steam_credentials() -> Config {
    let term = Term::stdout();
    let _ = term.clear_screen();
    
    println!("{}", style("Steam Credentials Configuration").cyan().bold());
    println!("{}", style("────────────────────────────────").cyan());
    println!("{}", style("Steam credentials are required to download DayZ Server files.").dim());
    println!("{}", style("These credentials will be stored locally on your machine with basic encryption.").dim());
    println!();
    
    let theme = ColorfulTheme::default();
    
    let username = Input::<String>::with_theme(&theme)
        .with_prompt("Steam username")
        .interact()
        .unwrap();
    
    let password = Password::with_theme(&theme)
        .with_prompt("Steam password")
        .interact()
        .unwrap();
    
    let docker_compose_version = detect_docker_compose_version();
    
    let mut config = Config::new();
    config.steam_username = username;
    config.steam_password = password;
    config.encrypt_password();
    config.docker_compose_version = docker_compose_version;
    
    let config_path = get_config_path();
    if let Err(e) = config.save(&config_path) {
        eprintln!("{}", style(format!("Failed to save config: {}", e)).red());
    }
    
    config
}

fn generate_docker_compose(server: &ServerConfig, config: &Config) -> String {
    let mut mods_string = String::new();
    if !server.mods.is_empty() {
        mods_string = format!("-mod={};", server.mods.join(";"));
    }
    
    let compose_version = if config.docker_compose_version == 1 { "3" } else { "3.8" };
    
    format!(
        r#"version: '{}'
services:
  dayz-server:
    image: ich777/steamcmd:latest
    container_name: ferruz-dayz-server-{}
    restart: unless-stopped
    environment:
      - PUID=1000
      - PGID=1000
      - USERNAME={}
      - PASSWRD={}
      - GAME_ID=223350
      - GAME_NAME=DayZ
      - GAME_PORT={}
      - GAME_PARAMS=-config=serverDZ.cfg -BEPath=battleye -profiles=profiles {}
      - VALIDATE=false
      - UMASK=000
    ports:
      - {}:2302/udp
      - {}:2303/udp
      - {}:2304/udp
      - {}:2305/udp
      - {}:2306/udp
      - {}:27016/udp
    volumes:
      - ./data/dayz-server-{}:/serverdata
"#,
        compose_version,
        server.name, 
        config.steam_username, config.decrypt_password(), 
        server.port, mods_string,
        server.port, server.port + 1, server.port + 2, server.port + 3, server.port + 4, server.port + 14714,
        server.name
    )
}

fn generate_server_config(server: &ServerConfig) -> String {
    let password_line = match &server.password {
        Some(password) if !password.is_empty() => format!("password = \"{}\";", password),
        _ => "password = \"\";".to_string(),
    };

    format!(
        r#"hostname = "FerruZ - {} DayZ Server";
{}
passwordAdmin = "{}";
maxPlayers = {};
verifySignatures = 2;
forceSameBuild = 1;
template_ls = "dayzOffline.{}";
instanceId = 1;
loginQueueConcurrentPlayers = 5;
loginQueueMaxPlayers = 500;
enableWhitelist = 0;
"#,
        server.name, password_line, server.admin_password, server.max_players, server.location
    )
}

fn handle_interactive_deploy() -> DeployArgs {
    let term = Term::stdout();
    let _ = term.clear_screen();
    
    println!("{}", style("DayZ Server Deployment Wizard").cyan().bold());
    println!("{}", style("────────────────────────────").cyan());
    println!();
    
    let theme = ColorfulTheme::default();
    
    let name: String = Input::with_theme(&theme)
        .with_prompt("Server name")
        .interact()
        .unwrap();
    
    let port: u16 = Input::with_theme(&theme)
        .with_prompt("Server port")
        .default(2302)
        .interact()
        .unwrap();
    
    let max_players: u16 = Input::with_theme(&theme)
        .with_prompt("Max players")
        .default(60)
        .interact()
        .unwrap();
    
    let maps = vec!["chernarusplus", "livonia", "namalsk", "esseker", "takistan"];
    let location_idx = Select::with_theme(&theme)
        .with_prompt("Select map/location")
        .default(0)
        .items(&maps)
        .interact()
        .unwrap();
    let location = maps[location_idx].to_string();
    
    let use_password = Confirm::with_theme(&theme)
        .with_prompt("Set server password?")
        .default(false)
        .interact()
        .unwrap();
    
    let password = if use_password {
        Some(Password::with_theme(&theme)
            .with_prompt("Server password")
            .interact()
            .unwrap())
    } else {
        None
    };
    
    let admin_password = Password::with_theme(&theme)
        .with_prompt("Admin password")
        .with_confirmation("Confirm admin password", "Passwords don't match")
        .interact()
        .unwrap();
    
    let use_mods = Confirm::with_theme(&theme)
        .with_prompt("Add workshop mods?")
        .default(false)
        .interact()
        .unwrap();
    
    let mods = if use_mods {
        Some(Input::<String>::with_theme(&theme)
            .with_prompt("Mod workshop IDs (comma separated)")
            .interact()
            .unwrap())
    } else {
        None
    };
    
    let custom_config = Confirm::with_theme(&theme)
        .with_prompt("Use custom server configuration file?")
        .default(false)
        .interact()
        .unwrap();
    
    let config = if custom_config {
        Some(Input::<String>::with_theme(&theme)
            .with_prompt("Path to server configuration file")
            .interact()
            .unwrap())
    } else {
        None
    };
    
    DeployArgs {
        name: Some(name),
        port: Some(port),
        max_players: Some(max_players),
        config,
        mods,
        password,
        admin_password: Some(admin_password),
        location: Some(location),
        interactive: false, // We've already done interactive setup
    }
}

fn deploy_server(args: DeployArgs, config_path: &Path) {
    let mut config = Config::load(config_path).unwrap_or_else(|_| Config::new());
    
    if config.steam_username.is_empty() || config.steam_password.is_empty() {
        config = configure_steam_credentials();
    }
    
    // If interactive mode is enabled, run the interactive setup instead
    let args = if args.interactive {
        handle_interactive_deploy()
    } else {
        args
    };
    
    // Handle required fields that might be None
    let name = match args.name {
        Some(name) => name,
        None => {
            println!("{}", style("Server name is required").red());
            return;
        }
    };
    
    // Check if server with this name already exists
    if config.servers.iter().any(|s| s.name == name) {
        println!("{}", style(format!("Server with name '{}' already exists", name)).red());
        return;
    }
    
    // Parse mod IDs if provided
    let mod_ids = args.mods.map(|m| {
        m.split(',')
            .map(|id| id.trim().to_string())
            .collect::<Vec<_>>()
    }).unwrap_or_default();
    
    let server = ServerConfig {
        name: name.clone(),
        port: args.port.unwrap_or(2302),
        max_players: args.max_players.unwrap_or(60),
        mods: mod_ids,
        container_id: None,
        password: args.password,
        admin_password: args.admin_password.unwrap_or_else(|| "changeme".to_string()),
        location: args.location.unwrap_or_else(|| "chernarusplus".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    println!("{}", style(format!("Deploying DayZ server: {}", name)).cyan());
    
    // Generate and save docker-compose file
    let docker_compose = generate_docker_compose(&server, &config);
    let docker_compose_path = get_docker_compose_path(&name);
    
    fs::write(&docker_compose_path, docker_compose).unwrap_or_else(|e| {
        eprintln!("{}", style(format!("Failed to save docker-compose file: {}", e)).red());
    });
    
    // Create directory structure for server data
    let data_dir = get_data_dir(&name);
    
    // Create server config if no custom config is provided
    if let Some(custom_config) = args.config {
        // Copy custom config
        if let Err(e) = fs::copy(&custom_config, data_dir.join("serverDZ.cfg")) {
            eprintln!("{}", style(format!("Failed to copy custom server configuration: {}", e)).red());
        }
        println!("{}", style("Using custom server configuration").dim());
    } else {
        // Generate default config
        let server_cfg = generate_server_config(&server);
        fs::write(data_dir.join("serverDZ.cfg"), server_cfg).unwrap_or_else(|e| {
            eprintln!("{}", style(format!("Failed to save server configuration: {}", e)).red());
        });
        println!("{}", style("Generated default server configuration").dim());
    }
    
    // Add server to config
    config.servers.push(server);
    config.save(config_path).unwrap_or_else(|e| {
        eprintln!("{}", style(format!("Failed to update config: {}", e)).red());
    });
    
    // Show progress indication
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    spinner.set_message(format!("Starting server '{}'...", name));
    spinner.enable_steady_tick(Duration::from_millis(100));
    
    // Start the server
    start_server(&name, &config);
    
    spinner.finish_with_message(format!("Server '{}' deployed successfully!", name));
    println!();
    println!("{}", style("Server files are stored at:").dim());
    println!("{}", style(data_dir.display()).cyan());
    println!();
    println!("{}", style("Note: Initial server startup may take some time as it downloads the DayZ server files.").yellow());
    println!("{}", style("Use the following command to view server logs:").dim());
    println!("{}", style(format!("ferruz logs {}", name)).cyan());
}

fn start_server(name: &str, config: &Config) -> bool {
    let docker_compose_path = get_docker_compose_path(name);
    
    if !docker_compose_path.exists() {
        println!("{}", style(format!("Server '{}' does not exist", name)).red());
        return false;
    }
    
    println!("{}", style(format!("Starting server '{}'...", name)).cyan());
    
    // Get the appropriate docker compose command
    let docker_cmd = docker_compose_cmd(config);
    
    let mut cmd = Command::new(&docker_cmd[0]);
    
    // Add the rest of the arguments
    for arg in docker_cmd.iter().skip(1) {
        cmd.arg(arg);
    }
    
    let output = cmd
        .arg("-f")
        .arg(&docker_compose_path)
        .arg("up")
        .arg("-d")
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                println!("{}", style(format!("Server '{}' started successfully!", name)).green());
                
                // Update container ID in config
                update_container_id(name);
                
                true
            } else {
                println!("{}", style(format!("Failed to start server '{}'", name)).red());
                println!("{}", style(String::from_utf8_lossy(&output.stderr)).red());
                false
            }
        }
        Err(e) => {
            println!("{}", style(format!("Failed to execute docker command: {}", e)).red());
            false
        }
    }
}

fn update_container_id(name: &str) {
    let config_path = get_config_path();
    let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    if let Some(server) = config.servers.iter_mut().find(|s| s.name == name) {
        // Get container ID
        let container_name = format!("ferruz-dayz-server-{}", name);
        let output = Command::new("docker")
            .arg("ps")
            .arg("-q")
            .arg("-f")
            .arg(format!("name={}", container_name))
            .output();
        
        if let Ok(output) = output {
            let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !container_id.is_empty() {
                server.container_id = Some(container_id);
                server.updated_at = Utc::now();
                config.save(&config_path).unwrap_or_else(|e| {
                    eprintln!("{}", style(format!("Failed to update config: {}", e)).red());
                });
            }
        }
    }
}

fn stop_server(name: &str, config: &Config) -> bool {
    let docker_compose_path = get_docker_compose_path(name);
    
    if !docker_compose_path.exists() {
        println!("{}", style(format!("Server '{}' does not exist", name)).red());
        return false;
    }
    
    println!("{}", style(format!("Stopping server '{}'...", name)).cyan());
    
    // Get the appropriate docker compose command
    let docker_cmd = docker_compose_cmd(config);
    
    let mut cmd = Command::new(&docker_cmd[0]);
    
    // Add the rest of the arguments
    for arg in docker_cmd.iter().skip(1) {
        cmd.arg(arg);
    }
    
    let output = cmd
        .arg("-f")
        .arg(&docker_compose_path)
        .arg("down")
        .output();
    
    match output {
        Ok(output) => {
            if output.status.success() {
                println!("{}", style(format!("Server '{}' stopped successfully!", name)).green());
                
                // Update container ID in config
                let config_path = get_config_path();
                let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
                
                if let Some(server) = config.servers.iter_mut().find(|s| s.name == name) {
                    server.container_id = None;
                    server.updated_at = Utc::now();
                    config.save(&config_path).unwrap_or_else(|e| {
                        eprintln!("{}", style(format!("Failed to update config: {}", e)).red());
                    });
                }
                
                true
            } else {
                println!("{}", style(format!("Failed to stop server '{}'", name)).red());
                println!("{}", style(String::from_utf8_lossy(&output.stderr)).red());
                false
            }
        }
        Err(e) => {
            println!("{}", style(format!("Failed to execute docker command: {}", e)).red());
            false
        }
    }
}

fn restart_server(name: &str, config: &Config) {
    println!("{}", style(format!("Restarting server '{}'...", name)).cyan());
    
    if stop_server(name, config) {
        // Give it a moment to fully stop
        std::thread::sleep(Duration::from_secs(2));
        start_server(name, config);
    }
}

fn list_servers(config: &Config) {
    if config.servers.is_empty() {
        println!("{}", style("No DayZ servers have been deployed").yellow());
        return;
    }
    
    println!("{}", style("FerruZ DayZ Servers").cyan().bold());
    println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
    println!("{:<15} {:<8} {:<10} {:<10} {:<15}", 
        style("Name").bold(),
        style("Port").bold(),
        style("Players").bold(),
        style("Status").bold(),
        style("Location").bold());
    println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
    
    for server in &config.servers {
        let status = if let Some(container_id) = &server.container_id {
            let output = Command::new("docker")
                .arg("ps")
                .arg("--filter")
                .arg(format!("id={}", container_id))
                .arg("--format")
                .arg("{{.Status}}")
                .output();
            
            match output {
                Ok(output) => {
                    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if status.is_empty() {
                        style("Stopped").red().to_string()
                    } else if status.contains("Up") {
                        style("Running").green().to_string()
                    } else {
                        style(&status).yellow().to_string()
                    }
                }
                Err(_) => style("Unknown").yellow().to_string(),
            }
        } else {
            style("Stopped").red().to_string()
        };
        
        println!("{:<15} {:<8} {:<10} {:<10} {:<15}", 
            server.name, 
            server.port,
            server.max_players,
            status,
            server.location);
    }
    
    println!();
    println!("{}", style("Use 'ferruz status <name>' for detailed server information").dim());
}

fn show_server_logs(name: &str, follow: bool, lines: usize, config: &Config) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Check if the container is running
    let mut docker_args = vec!["logs"];
    
    if follow {
        docker_args.push("--follow");
    }
    
    docker_args.push("--tail");
    let binding = lines.to_string();
    docker_args.push(&binding);
    docker_args.push(&container_name);
    
    println!("{}", style(format!("Showing logs for server '{}':", name)).cyan());
    println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
    
    let status = Command::new("docker")
        .args(&docker_args)
        .status();
    
    match status {
        Ok(_) => {
            // Command completed successfully, nothing to do
            if !follow {
                println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
                println!("{}", style(format!("End of logs for server '{}'", name)).dim());
            }
        }
        Err(e) => {
            println!("{}", style(format!("Failed to get logs: {}", e)).red());
        }
    }
}

fn execute_command(name: &str, command_args: Vec<String>) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Check if the container is running
    if server.container_id.is_none() {
        println!("{}", style(format!("Server '{}' is not running", name)).red());
        return;
    }
    
    // Build the command
    let mut docker_args = vec!["exec", &container_name];
    docker_args.extend(command_args.iter().map(|s| s.as_str()));
    
    println!("{}", style(format!("Executing command on server '{}':", name)).cyan());
    println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
    
    let status = Command::new("docker")
        .args(&docker_args)
        .status();
    
    match status {
        Ok(status) => {
            if !status.success() {
                println!("{}", style(format!("Command failed with exit code: {}", status)).red());
            }
        }
        Err(e) => {
            println!("{}", style(format!("Failed to execute command: {}", e)).red());
        }
    }
}

fn show_server_status(name: &str) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    println!("{}", style(format!("Status for DayZ Server: {}", name)).cyan().bold());
    println!("{}", style("─────────────────────────────────────────────────────────────").cyan());
    
    // Container status
    let container_status = if let Some(container_id) = &server.container_id {
        let output = Command::new("docker")
            .args(&["inspect", "--format", "{{.State.Status}}", container_id])
            .output();
        
        match output {
            Ok(output) => {
                let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if status.is_empty() {
                    "Not running".to_string()
                } else {
                    status
                }
            }
            Err(_) => "Unknown".to_string(),
        }
    } else {
        "Not running".to_string()
    };
    
    let status_color = if container_status == "running" {
        style(&container_status).green().to_string()
    } else if container_status == "Not running" {
        style(&container_status).red().to_string()
    } else {
        style(&container_status).yellow().to_string()
    };
    
    // Get container stats
    let stats_output = if let Some(container_id) = &server.container_id {
        let output = Command::new("docker")
            .args(&["stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}", container_id])
            .output();
        
        match output {
            Ok(output) => {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            Err(_) => "".to_string(),
        }
    } else {
        "".to_string()
    };
    
    let mut cpu_usage = "N/A".to_string();
    let mut mem_usage = "N/A".to_string();
    let mut net_io = "N/A".to_string();
    
    if !stats_output.is_empty() {
        let stats: Vec<&str> = stats_output.split('|').collect();
        if stats.len() >= 3 {
            cpu_usage = stats[0].to_string();
            mem_usage = stats[1].to_string();
            net_io = stats[2].to_string();
        }
    }
    
    // Get server info from config
    println!("{:<20} {}", style("Name:").bold(), server.name);
    println!("{:<20} {}", style("Status:").bold(), status_color);
    println!("{:<20} {}", style("Game Port:").bold(), server.port);
    println!("{:<20} {}", style("Max Players:").bold(), server.max_players);
    println!("{:<20} {}", style("Map/Location:").bold(), server.location);
    println!("{:<20} {}", style("Mods Installed:").bold(), server.mods.len());
    println!("{:<20} {}", style("Created:").bold(), server.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("{:<20} {}", style("Last Updated:").bold(), server.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if container_status == "running" {
        println!();
        println!("{}", style("Resource Usage:").bold());
        println!("{:<20} {}", style("CPU:").bold(), cpu_usage);
        println!("{:<20} {}", style("Memory:").bold(), mem_usage);
        println!("{:<20} {}", style("Network I/O:").bold(), net_io);
    }
    
    // Display installed mods if any
    if !server.mods.is_empty() {
        println!();
        println!("{}", style("Installed Mods:").bold());
        for (i, mod_id) in server.mods.iter().enumerate() {
            println!("{:<4} {}", i + 1, mod_id);
        }
    }
    
    println!();
    println!("{}", style("Server Data Path:").bold());
    println!("{}", style(get_data_dir(&server.name).display()).cyan());
    
    println!();
    println!("{}", style("Quick Commands:").dim());
    println!("{:<4} {}", style("•").dim(), style(format!("ferruz logs {}", name)).cyan());
    println!("{:<4} {}", style("•").dim(), style(format!("ferruz restart {}", name)).cyan());
    println!("{:<4} {}", style("•").dim(), style(format!("ferruz shell {}", name)).cyan());
}

fn update_server(name: &str, validate: bool, config: &Config) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    println!("{}", style(format!("Updating server '{}'...", name)).cyan());
    
    // First, stop the server
    stop_server(name, &config);
    
    // Update the validate environment variable
    let validate_option = if validate { "true" } else { "false" };
    
    // Get the docker compose path
    let docker_compose_path = get_docker_compose_path(name);
    
    // Read the current docker-compose file
    let compose_content = fs::read_to_string(&docker_compose_path)
        .unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to read docker-compose file: {}", e)).red());
            String::new()
        });
    
    // Replace the validate variable
    let updated_content = compose_content.replace("VALIDATE=false", &format!("VALIDATE={}", validate_option));
    
    // Write the updated docker-compose file
    fs::write(&docker_compose_path, updated_content)
        .unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to update docker-compose file: {}", e)).red());
        });
    
    // Start the server with the updated docker-compose file
    println!("{}", style("Starting server with update process...").cyan());
    start_server(name, &config);
    
    // Reset the validate flag after update process starts
    std::thread::sleep(Duration::from_secs(5));
    
    println!("{}", style(format!("Update process initiated for server '{}'", name)).green());
    println!("{}", style("The server is now updating. This may take some time.").yellow());
    println!("{}", style(format!("You can check progress with: ferruz logs {}", name)).dim());
}

fn list_mods(name: &str) {
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    println!("{}", style(format!("Mods installed on server '{}':", name)).cyan().bold());
    println!("{}", style("───────────────────────────────────────────").cyan());
    
    if server.mods.is_empty() {
        println!("{}", style("No mods are currently installed").yellow());
        return;
    }
    
    println!("{:<5} {:<15}", style("#").bold(), style("Workshop ID").bold());
    println!("{}", style("───────────────────────────────────────────").cyan());
    
    for (i, mod_id) in server.mods.iter().enumerate() {
        println!("{:<5} {:<15}", i + 1, mod_id);
    }
}

fn add_mods(name: &str, mods: &str, config: &Config) {
    // Check if the server exists
    let config_path = get_config_path();
    let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server_index = match config.servers.iter().position(|s| s.name == name) {
        Some(index) => index,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Parse mod IDs
    let new_mods: Vec<String> = mods
        .split(',')
        .map(|id| id.trim().to_string())
        .collect();
    
    if new_mods.is_empty() {
        println!("{}", style("No valid mod IDs provided").red());
        return;
    }
    
    // Add new mods to the server
    let mut updated = false;
    
    for mod_id in new_mods.iter() {
        if !config.servers[server_index].mods.contains(mod_id) {
            config.servers[server_index].mods.push(mod_id.clone());
            updated = true;
            println!("{}", style(format!("Added mod {}", mod_id)).green());
        } else {
            println!("{}", style(format!("Mod {} is already installed", mod_id)).yellow());
        }
    }
    
    if updated {
        // Update the config
        config.servers[server_index].updated_at = Utc::now();
        config.save(&config_path).unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to save config: {}", e)).red());
        });
        
        // Update docker-compose file
        let server = &config.servers[server_index];
        let docker_compose = generate_docker_compose(&server, &config);
        let docker_compose_path = get_docker_compose_path(&name);
        
        fs::write(&docker_compose_path, docker_compose).unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to update docker-compose file: {}", e)).red());
        });
        
        // Ask if user wants to restart the server
        let theme = ColorfulTheme::default();
        let restart = Confirm::with_theme(&theme)
            .with_prompt("Would you like to restart the server now to apply changes?")
            .default(true)
            .interact()
            .unwrap();
        
        if restart {
            restart_server(name, &config);
        } else {
            println!("{}", style("Remember to restart the server to apply the mod changes").yellow());
        }
    }
}

fn remove_mods(name: &str, mods: &str, config: &Config) {
    // Check if the server exists
    let config_path = get_config_path();
    let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server_index = match config.servers.iter().position(|s| s.name == name) {
        Some(index) => index,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Parse mod IDs to remove
    let remove_mods: Vec<String> = mods
        .split(',')
        .map(|id| id.trim().to_string())
        .collect();
    
    if remove_mods.is_empty() {
        println!("{}", style("No valid mod IDs provided").red());
        return;
    }
    
    // Remove mods from the server
    let mut updated = false;
    
    for mod_id in remove_mods.iter() {
        if let Some(index) = config.servers[server_index].mods.iter().position(|m| m == mod_id) {
            config.servers[server_index].mods.remove(index);
            updated = true;
            println!("{}", style(format!("Removed mod {}", mod_id)).green());
        } else {
            println!("{}", style(format!("Mod {} is not installed", mod_id)).yellow());
        }
    }
    
    if updated {
        // Update the config
        config.servers[server_index].updated_at = Utc::now();
        config.save(&config_path).unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to save config: {}", e)).red());
        });
        
        // Update docker-compose file
        let server = &config.servers[server_index];
        let docker_compose = generate_docker_compose(&server, &config);
        let docker_compose_path = get_docker_compose_path(&name);
        
        fs::write(&docker_compose_path, docker_compose).unwrap_or_else(|e| {
            println!("{}", style(format!("Failed to update docker-compose file: {}", e)).red());
        });
        
        // Ask if user wants to restart the server
        let theme = ColorfulTheme::default();
        let restart = Confirm::with_theme(&theme)
            .with_prompt("Would you like to restart the server now to apply changes?")
            .default(true)
            .interact()
            .unwrap();
        
        if restart {
            restart_server(name, &config);
        } else {
            println!("{}", style("Remember to restart the server to apply the mod changes").yellow());
        }
    }
}

fn update_mods(name: &str, config: &Config) {
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    if server.mods.is_empty() {
        println!("{}", style("No mods are installed on this server").yellow());
        return;
    }
    
    println!("{}", style(format!("Updating {} mods on server '{}'...", server.mods.len(), name)).cyan());
    
    // Since the mods are managed by SteamCMD inside the container,
    // we need to restart the server with validate flag set to update them
    update_server(name, true, &config);
}

fn open_shell(name: &str) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Check if the server is running
    if server.container_id.is_none() {
        println!("{}", style(format!("Server '{}' is not running", name)).red());
        return;
    }
    
    println!("{}", style(format!("Opening shell in server '{}'...", name)).cyan());
    
    // Execute interactive shell
    let status = Command::new("docker")
        .args(&["exec", "-it", &container_name, "/bin/bash"])
        .status();
    
    match status {
        Ok(_) => {},
        Err(e) => {
            println!("{}", style(format!("Failed to open shell: {}", e)).red());
        }
    }
}

fn backup_server(name: &str, output_dir: Option<String>) {
    let container_name = format!("ferruz-dayz-server-{}", name);
    
    // Check if the server exists
    let config_path = get_config_path();
    let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    // Determine backup directory
    let backup_dir = match output_dir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let mut path = get_ferruz_dir();
            path.push("backups");
            fs::create_dir_all(&path).unwrap_or_else(|_| {
                eprintln!("Failed to create backups directory");
            });
            path
        }
    };
    
    // Create timestamp for backup filename
    let now = Utc::now();
    let timestamp = now.format("%Y%m%d_%H%M%S");
    let backup_filename = format!("ferruz_backup_{}_{}.tar.gz", name, timestamp);
    let backup_path = backup_dir.join(&backup_filename);
    
    println!("{}", style(format!("Creating backup of server '{}'...", name)).cyan());
    
    // Create temporary directory for backup
    let mut temp_dir = get_ferruz_dir();
    temp_dir.push("temp");
    fs::create_dir_all(&temp_dir).unwrap_or_else(|_| {
        eprintln!("Failed to create temporary directory");
    });
    
    // Copy server data to temporary directory
    let server_data_dir = get_data_dir(name);
    let temp_server_dir = temp_dir.join(format!("dayz-server-{}", name));
    
    // Create progress bar
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Copying server data...");
    
    // Copy files
    if let Err(e) = copy_dir_all(&server_data_dir, &temp_server_dir) {
        spinner.finish_with_message(format!("Failed to copy server data: {}", e));
        return;
    }
    
    spinner.set_message("Creating backup archive...");
    
    // Create tar.gz archive
    let tar_status = Command::new("tar")
        .args(&["-czf", backup_path.to_str().unwrap(), "-C", temp_dir.to_str().unwrap(), &format!("dayz-server-{}", name)])
        .status();
    
    match tar_status {
        Ok(status) => {
            if status.success() {
                // Clean up temporary directory
                fs::remove_dir_all(&temp_dir).ok();
                
                spinner.finish_with_message(format!("Backup created: {}", backup_path.display()));
                
                // Update last backup time
                config.last_backup_check = Some(now);
                config.save(&config_path).unwrap_or_else(|e| {
                    println!("{}", style(format!("Failed to update config: {}", e)).red());
                });
            } else {
                spinner.finish_with_message(format!("Failed to create backup archive"));
            }
        }
        Err(e) => {
            spinner.finish_with_message(format!("Failed to create backup archive: {}", e));
        }
    }
}

fn restore_backup(name: &str, backup_path: &str, config: &Config) {
    let backup_file = Path::new(backup_path);
    if !backup_file.exists() {
        println!("{}", style(format!("Backup file not found: {}", backup_path)).red());
        return;
    }
    
    // Check if the server exists
    let config_path = get_config_path();
    let config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    let server = match config.servers.iter().find(|s| s.name == name) {
        Some(server) => server,
        None => {
            println!("{}", style(format!("Server '{}' does not exist", name)).red());
            return;
        }
    };
    
    println!("{}", style(format!("Restoring backup to server '{}'...", name)).cyan());
    
    // Ask for confirmation
    let theme = ColorfulTheme::default();
    let confirm = Confirm::with_theme(&theme)
        .with_prompt("This will overwrite current server data. Are you sure?")
        .default(false)
        .interact()
        .unwrap();
    
    if !confirm {
        println!("{}", style("Restore cancelled").yellow());
        return;
    }
    
    // Stop the server if it's running
    if server.container_id.is_some() {
        stop_server(name, &config);
    }
    
    // Create temporary directory for extraction
    let mut temp_dir = get_ferruz_dir();
    temp_dir.push("temp");
    fs::create_dir_all(&temp_dir).unwrap_or_else(|_| {
        eprintln!("Failed to create temporary directory");
    });
    
    // Create progress bar
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_message("Extracting backup...");
    
    // Extract backup
    let extract_status = Command::new("tar")
        .args(&["-xzf", backup_path, "-C", temp_dir.to_str().unwrap()])
        .status();
    
    match extract_status {
        Ok(status) => {
            if !status.success() {
                spinner.finish_with_message("Failed to extract backup archive");
                return;
            }
        }
        Err(e) => {
            spinner.finish_with_message(format!("Failed to extract backup archive: {}", e));
            return;
        }
    }
    
    // Get server data directory
    let server_data_dir = get_data_dir(name);
    let temp_server_dir = temp_dir.join(format!("dayz-server-{}", name));
    
    spinner.set_message("Restoring server data...");
    
    // Remove current server data
    match fs::remove_dir_all(&server_data_dir) {
        Ok(_) => {},
        Err(e) => {
            spinner.finish_with_message(format!("Failed to remove current server data: {}", e));
            return;
        }
    }
    
    // Restore from backup
    match copy_dir_all(&temp_server_dir, &server_data_dir) {
        Ok(_) => {},
        Err(e) => {
            spinner.finish_with_message(format!("Failed to restore server data: {}", e));
            return;
        }
    }
    
    // Clean up temporary directory
    fs::remove_dir_all(&temp_dir).ok();
    
    spinner.finish_with_message("Server data restored successfully");
    
    // Ask if they want to start the server
    let should_start_server = Confirm::with_theme(&theme)
        .with_prompt("Would you like to start the server now?")
        .default(true)
        .interact()
        .unwrap();
    
    if should_start_server {
        start_server(name, &config);
    }
}

// Helper function to recursively copy a directory
fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        
        if file_type.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            let _ = fs::copy(&src_path, &dst_path)?;
        }
    }
    
    Ok(())
}

fn main() {
    // Verify Docker is installed
    if which("docker").is_err() {
        println!("{}", style("Docker is not installed or not in your PATH").red());
        println!("Please install Docker from https://docs.docker.com/get-docker/");
        return;
    }
    
    // Load config
    let config_path = get_config_path();
    let mut config = Config::load(&config_path).unwrap_or_else(|_| Config::new());
    
    // Check docker-compose version if not already set
    if config.docker_compose_version == 0 {
        config.docker_compose_version = detect_docker_compose_version();
        config.save(&config_path).unwrap_or_else(|_| {});
    }
    
    // Check Docker Compose v1 or Docker Compose v2
    let docker_cmd = docker_compose_cmd(&config);
    let mut test_command = Command::new(&docker_cmd[0]);
    for arg in docker_cmd.iter().skip(1) {
        test_command.arg(arg);
    }
    test_command.arg("version");
    
    if test_command.status().is_err() {
        println!("{}", style("Docker Compose is not installed or not in your PATH").red());
        println!("Please install Docker Compose from https://docs.docker.com/compose/install/");
        return;
    }
    
    // Parse command-line arguments
    let cli = Cli::parse();
    
    match cli.command {
        Some(Commands::Deploy(args)) => {
            deploy_server(args, &config_path);
        },
        Some(Commands::Start { name }) => {
            start_server(&name, &config);
        },
        Some(Commands::Stop { name }) => {
            stop_server(&name, &config);
        },
        Some(Commands::Restart { name }) => {
            restart_server(&name, &config);
        },
        Some(Commands::List {}) => {
            list_servers(&config);
        },
        Some(Commands::Config {}) => {
            configure_steam_credentials();
            println!("{}", style("Steam credentials configured successfully!").green());
        },
        Some(Commands::Logs(args)) => {
            show_server_logs(&args.name, args.follow, args.lines, &config);
        },
        Some(Commands::Execute { name, command }) => {
            execute_command(&name, command);
        },
        Some(Commands::Status { name }) => {
            show_server_status(&name);
        },
        Some(Commands::Update { name, validate }) => {
            update_server(&name, validate, &config);
        },
        Some(Commands::Mods(cmd)) => {
            match cmd {
                ModsCommand::List { name } => list_mods(&name),
                ModsCommand::Add { name, mods } => add_mods(&name, &mods, &config),
                ModsCommand::Remove { name, mods } => remove_mods(&name, &mods, &config),
                ModsCommand::Update { name } => update_mods(&name, &config),
            }
        },
        Some(Commands::Shell { name }) => {
            open_shell(&name);
        },
        Some(Commands::Backup { name, output }) => {
            backup_server(&name, output);
        },
        Some(Commands::Restore { name, path }) => {
            restore_backup(&name, &path, &config);
        },
        None => {
            // If no command is provided, show a welcome message and the server list
            let term = Term::stdout();
            let _ = term.clear_screen();
            
            println!("{}", style("Welcome to FerruZ - DayZ Server Manager").cyan().bold());
            println!("{}", style("────────────────────────────────────────").cyan());
            println!();
            
            if config.servers.is_empty() {
                println!("{}", style("No DayZ servers have been deployed yet.").yellow());
                println!();
                println!("{}", style("To deploy your first server, run:").dim());
                println!("{}", style("  ferruz deploy").cyan());
                println!();
                println!("{}", style("To see all available commands, run:").dim());
                println!("{}", style("  ferruz --help").cyan());
            } else {
                list_servers(&config);
                println!();
                println!("{}", style("Use 'ferruz --help' for a list of commands").dim());
            }
            println!("{}", style("Happy gaming!").green());
            println!("{}", style("────────────────────────────────────────").cyan());
        }
    }
}