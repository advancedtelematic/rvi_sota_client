extern crate chan;
extern crate chan_signal;
extern crate crossbeam;
extern crate env_logger;
extern crate getopts;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate sota;
extern crate time;

use chan::{Sender, Receiver};
use chan_signal::Signal;
use env_logger::LogBuilder;
use getopts::Options;
use log::{LogLevelFilter, LogRecord};
use std::{env, process, thread};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use sota::datatype::{Command, Config, Event};
use sota::gateway::{Console, Gateway, Http};
#[cfg(feature = "rvi")]
use sota::gateway::DBus;
#[cfg(feature = "socket")]
use sota::gateway::Socket;
#[cfg(feature = "websocket")]
use sota::gateway::Websocket;
use sota::broadcast::Broadcast;
use sota::http::{AuthClient, TlsClient};
use sota::interpreter::{CommandExec, CommandMode, CommandInterpreter,
                        EventInterpreter, Interpreter};
use sota::pacman::PacMan;
#[cfg(feature = "rvi")]
use sota::rvi::{Edge, Services};
use sota::uptane::Uptane;


macro_rules! exit {
    ($code:expr, $fmt:expr, $($arg:tt)*) => {{
        println!($fmt, $($arg)*);
        process::exit($code);
    }}
}


fn main() {
    let version = start_logging();
    let config = build_config(&version);
    TlsClient::init(config.tls_data());
    let auth = config.initial_auth().unwrap_or_else(|err| exit!(2, "{}", err));

    let (ctx, crx) = chan::async::<CommandExec>();
    let (etx, erx) = chan::async::<Event>();
    let mut broadcast = Broadcast::new(erx);
    etx.send(Event::NotAuthenticated);

    crossbeam::scope(|scope| {
        let signals = chan_signal::notify(&[Signal::INT, Signal::TERM]);
        scope.spawn(move || start_signal_handler(&signals));

        if config.core.polling {
            let poll_tick = config.core.polling_sec;
            let poll_ctx  = ctx.clone();
            scope.spawn(move || start_update_poller(poll_tick, &poll_ctx));
        }

        if config.gateway.console {
            let cons_ctx = ctx.clone();
            let cons_erx = broadcast.subscribe();
            scope.spawn(move || Console.start(cons_ctx, cons_erx));
        }

        if config.gateway.dbus {
            #[cfg(not(feature = "rvi"))]
            exit!(2, "{}", "dbus gateway requires 'rvi' binary feature");
            #[cfg(feature = "rvi")] {
                let dbus_ctx = ctx.clone();
                let dbus_erx = broadcast.subscribe();
                let mut dbus = DBus { cfg: config.dbus.clone() };
                scope.spawn(move || dbus.start(dbus_ctx, dbus_erx));
            }
        }

        if config.gateway.http {
            let http_ctx = ctx.clone();
            let http_erx = broadcast.subscribe();
            let mut http = Http { server: *config.network.http_server };
            scope.spawn(move || http.start(http_ctx, http_erx));
        }

        if config.gateway.rvi {
            #[cfg(not(feature = "rvi"))]
            exit!(2, "{}", "rvi gateway requires 'rvi' binary feature");
            #[cfg(feature = "rvi")] {
                let services = Services::new(config.rvi.clone(), format!("{}", config.device.uuid), etx.clone());
                let mut edge = Edge::new(services, config.network.rvi_edge_server.clone(), config.rvi.client.clone());
                scope.spawn(move || edge.start());
            }
        }

        if config.gateway.socket {
            #[cfg(not(feature = "socket"))]
            exit!(2, "{}", "socket gateway requires 'socket' binary feature");
            #[cfg(feature = "socket")] {
                let socket_ctx = ctx.clone();
                let socket_erx = broadcast.subscribe();
                let mut socket = Socket {
                    cmd_sock: config.network.socket_commands_path.clone(),
                    ev_sock:  config.network.socket_events_path.clone()
                };
                scope.spawn(move || socket.start(socket_ctx, socket_erx));
            }
        }

        if config.gateway.websocket {
            #[cfg(not(feature = "websocket"))]
            exit!(2, "{}", "websocket gateway requires 'websocket' binary feature");
            #[cfg(feature = "websocket")] {
                let ws_ctx = ctx.clone();
                let ws_erx = broadcast.subscribe();
                let mut ws = Websocket { server: config.network.websocket_server.clone() };
                scope.spawn(move || ws.start(ws_ctx, ws_erx));
            }
        }

        let mut event_int = EventInterpreter {
            initial: config.device.report_on_start,
            loop_tx: etx.clone(),
            auth:    auth.clone(),
            pacman:  config.device.package_manager.clone(),
            auto_dl: config.device.auto_download,
            sysinfo: config.device.system_info.clone(),
            treehub: config.tls.as_ref().map_or(None, |tls| Some(tls.server.join("/treehub"))),
        };
        let ei_erx = broadcast.subscribe();
        let ei_ctx = ctx.clone();
        scope.spawn(move || event_int.run(ei_erx, ei_ctx));

        scope.spawn(move || {
            let mut mode = CommandMode::Sota;
            if let PacMan::Uptane = config.device.package_manager {
                let uptane = Uptane::new(&config).unwrap_or_else(|err| exit!(2, "couldn't start uptane: {}", err));
                mode = CommandMode::Uptane(Rc::new(RefCell::new(uptane)));
            }
            #[cfg(feature = "rvi")] {
                if config.gateway.rvi {
                    let services = Services::new(config.rvi.clone(), format!("{}", config.device.uuid), etx.clone());
                    mode = CommandMode::Rvi(Rc::new(RefCell::new(services)));
                }
            }

            let http = Box::new(AuthClient::from(auth.clone()));
            let mut cmd_int = CommandInterpreter {
                mode:   mode,
                config: config,
                auth:   auth,
                http:   http,
            };
            cmd_int.run(crx, etx)
        });

        scope.spawn(move || broadcast.start());
    });
}

fn start_logging() -> String {
    let version = option_env!("SOTA_VERSION").unwrap_or("unknown");

    let mut builder = LogBuilder::new();
    builder.format(move |record: &LogRecord| {
        let timestamp = format!("{}", time::now_utc().rfc3339());
        format!("{} ({}): {} - {}", timestamp, version, record.level(), record.args())
    });
    builder.filter(Some("hyper"), LogLevelFilter::Info);
    builder.parse(&env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string()));
    builder.init().expect("builder already initialized");

    version.to_string()
}

fn start_signal_handler(signals: &Receiver<Signal>) {
    loop {
        match signals.recv() {
            Some(Signal::INT) | Some(Signal::TERM) => process::exit(0),
            _ => ()
        }
    }
}

fn start_update_poller(interval: u64, ctx: &Sender<CommandExec>) {
    info!("Polling for new updates every {} seconds.", interval);
    let (etx, erx) = chan::async::<Event>();
    loop {
        ctx.send(CommandExec { cmd: Command::GetUpdateRequests, etx: Some(etx.clone()) });
        let _ = erx.recv(); // wait for the response
        thread::sleep(Duration::from_secs(interval));
    }
}

fn build_config(version: &str) -> Config {
    let args     = env::args().collect::<Vec<String>>();
    let program  = args[0].clone();
    let mut opts = Options::new();

    opts.optflag("h", "help", "print this help menu then quit");
    opts.optflag("p", "print", "print the parsed config then quit");
    opts.optflag("v", "version", "print the version then quit");
    opts.optopt("c", "config", "change config path", "PATH");

    opts.optopt("", "report-on-start", "send system info, packages and manifest after initial authentication", "BOOL");

    opts.optopt("", "auth-server", "change the auth server", "URL");
    opts.optopt("", "auth-client-id", "change the auth client id", "ID");
    opts.optopt("", "auth-client-secret", "change the auth client secret", "SECRET");

    opts.optopt("", "core-server", "change the core server", "URL");
    opts.optopt("", "core-polling", "toggle polling the core server for updates", "BOOL");
    opts.optopt("", "core-polling-sec", "change the core polling interval", "SECONDS");
    opts.optopt("", "core-ca-file", "pin the core CA certificates path", "PATH");

    opts.optopt("", "dbus-name", "change the dbus registration name", "NAME");
    opts.optopt("", "dbus-path", "change the dbus path", "PATH");
    opts.optopt("", "dbus-interface", "change the dbus interface name", "INTERFACE");
    opts.optopt("", "dbus-software-manager", "change the dbus software manager name", "NAME");
    opts.optopt("", "dbus-software-manager-path", "change the dbus software manager path", "PATH");
    opts.optopt("", "dbus-timeout", "change the dbus installation timeout", "TIMEOUT");

    opts.optopt("", "device-uuid", "change the device uuid", "UUID");
    opts.optopt("", "device-packages-dir", "change downloaded directory for packages", "PATH");
    opts.optopt("", "device-package-manager", "change the package manager", "MANAGER");
    opts.optopt("", "device-p12-path", "change the PKCS12 file path", "PATH");
    opts.optopt("", "device-p12-password", "change the PKCS12 file password", "PASSWORD");
    opts.optopt("", "device-system-info", "change the system information command", "PATH");

    opts.optopt("", "gateway-console", "toggle the console gateway", "BOOL");
    opts.optopt("", "gateway-dbus", "toggle the dbus gateway", "BOOL");
    opts.optopt("", "gateway-http", "toggle the http gateway", "BOOL");
    opts.optopt("", "gateway-rvi", "toggle the rvi gateway", "BOOL");
    opts.optopt("", "gateway-socket", "toggle the unix domain socket gateway", "BOOL");
    opts.optopt("", "gateway-websocket", "toggle the websocket gateway", "BOOL");

    opts.optopt("", "network-http-server", "change the http server gateway address", "ADDR");
    opts.optopt("", "network-rvi-edge-server", "change the rvi edge server gateway address", "ADDR");
    opts.optopt("", "network-socket-commands-path", "change the socket path for reading commands", "PATH");
    opts.optopt("", "network-socket-events-path", "change the socket path for sending events", "PATH");
    opts.optopt("", "network-websocket-server", "change the websocket gateway address", "ADDR");

    opts.optopt("", "rvi-client", "change the rvi client URL", "URL");
    opts.optopt("", "rvi-storage-dir", "change the rvi storage directory", "PATH");
    opts.optopt("", "rvi-timeout", "change the rvi timeout", "TIMEOUT");

    opts.optopt("", "tls-server", "change the TLS server", "URL");
    opts.optopt("", "tls-ca-file", "pin the TLS root CA certificate chain", "PATH");
    opts.optopt("", "tls-cert-file", "change the TLS certificate", "PATH");
    opts.optopt("", "tls-pkey-file", "change the TLS private key", "PASSWORD");

    opts.optopt("", "uptane-director-server", "change the Uptane Director server", "URL");
    opts.optopt("", "uptane-repo-server", "change the Uptane Repo server", "URL");
    opts.optopt("", "uptane-primary-ecu-serial", "change the primary ECU's serial", "TEXT");
    opts.optopt("", "uptane-metadata-path", "change the directory used to save Uptane metadata.", "PATH");
    opts.optopt("", "uptane-private-key-path", "change the path to the private key for the primary ECU", "PATH");
    opts.optopt("", "uptane-public-key-path", "change the path to the public key for the primary ECU", "PATH");

    let cli = opts.parse(&args[1..]).expect("couldn't parse args");
    if cli.opt_present("help") {
        exit!(0, "{}", opts.usage(&format!("Usage: {} [options]", program)));
    } else if cli.opt_present("version") {
        exit!(0, "{}", version);
    }
    let file = cli.opt_str("config").or_else(|| env::var("SOTA_CONFIG").ok()).expect("No config provided");
    let mut config = Config::load(&file).expect("Error loading config");

    config.auth.as_mut().map(|auth_cfg| {
        cli.opt_str("auth-server").map(|text| auth_cfg.server = text.parse().expect("Invalid auth-server URL"));
        cli.opt_str("auth-client-id").map(|id| auth_cfg.client_id = id);
        cli.opt_str("auth-client-secret").map(|secret| auth_cfg.client_secret = secret);
    });

    cli.opt_str("report-on-start").map(|x| config.device.report_on_start = x.parse().expect("Invalid report-on-start parameter."));

    cli.opt_str("core-server").map(|text| config.core.server = text.parse().expect("Invalid core-server URL"));
    cli.opt_str("core-polling").map(|polling| config.core.polling = polling.parse().expect("Invalid core-polling boolean"));
    cli.opt_str("core-polling-sec").map(|secs| config.core.polling_sec = secs.parse().expect("Invalid core-polling-sec"));
    cli.opt_str("core-ca-file").map(|path| config.core.ca_file = Some(path));

    cli.opt_str("dbus-name").map(|name| config.dbus.name = name);
    cli.opt_str("dbus-path").map(|path| config.dbus.path = path);
    cli.opt_str("dbus-interface").map(|interface| config.dbus.interface = interface);
    cli.opt_str("dbus-software-manager").map(|mgr| config.dbus.software_manager = mgr);
    cli.opt_str("dbus-software-manager-path").map(|mgr_path| config.dbus.software_manager_path = mgr_path);
    cli.opt_str("dbus-timeout").map(|timeout| config.dbus.timeout = timeout.parse().expect("Invalid dbus-timeout"));

    cli.opt_str("device-uuid").map(|uuid| config.device.uuid = uuid.parse().expect("Invalid device-uuid"));
    cli.opt_str("device-packages-dir").map(|path| config.device.packages_dir = path);
    cli.opt_str("device-package-manager").map(|text| config.device.package_manager = text.parse().expect("Invalid device-package-manager"));
    cli.opt_str("device-system-info").map(|cmd| config.device.system_info = Some(cmd));

    cli.opt_str("gateway-console").map(|console| config.gateway.console = console.parse().expect("Invalid gateway-console boolean"));
    cli.opt_str("gateway-dbus").map(|dbus| config.gateway.dbus = dbus.parse().expect("Invalid gateway-dbus boolean"));
    cli.opt_str("gateway-http").map(|http| config.gateway.http = http.parse().expect("Invalid gateway-http boolean"));
    cli.opt_str("gateway-rvi").map(|rvi| config.gateway.rvi = rvi.parse().expect("Invalid gateway-rvi boolean"));
    cli.opt_str("gateway-socket").map(|socket| config.gateway.socket = socket.parse().expect("Invalid gateway-socket boolean"));
    cli.opt_str("gateway-websocket").map(|websocket| config.gateway.websocket = websocket.parse().expect("Invalid gateway-websocket boolean"));

    cli.opt_str("network-http-server").map(|addr| config.network.http_server = addr.parse().expect("Invalid network-http-server"));
    cli.opt_str("network-rvi-edge-server").map(|addr| config.network.rvi_edge_server = addr.parse().expect("Invalid network-rvi-edge-server"));
    cli.opt_str("network-socket-commands-path").map(|path| config.network.socket_commands_path = path);
    cli.opt_str("network-socket-events-path").map(|path| config.network.socket_events_path = path);
    cli.opt_str("network-websocket-server").map(|server| config.network.websocket_server = server);

    cli.opt_str("rvi-client").map(|url| config.rvi.client = url.parse().expect("Invalid rvi-client URL"));
    cli.opt_str("rvi-storage-dir").map(|dir| config.rvi.storage_dir = dir);
    cli.opt_str("rvi-timeout").map(|timeout| config.rvi.timeout = Some(timeout.parse().expect("Invalid rvi-timeout")));

    config.tls.as_mut().map(|tls_cfg| {
        cli.opt_str("tls-server").map(|text| tls_cfg.server = text.parse().expect("Invalid tls-server URL"));
        cli.opt_str("tls-ca-file").map(|path| tls_cfg.ca_file = path);
        cli.opt_str("tls-cert-file").map(|path| tls_cfg.cert_file = path);
        cli.opt_str("tls-pkey-file").map(|path| tls_cfg.pkey_file = path);
    });

    cli.opt_str("uptane-director-server").map(|text| config.uptane.director_server = text.parse().expect("Invalid uptane-director-server URL"));
    cli.opt_str("uptane-repo-server").map(|text| config.uptane.repo_server = text.parse().expect("Invalid uptane-repo-server URL"));
    cli.opt_str("uptane-primary-ecu-serial").map(|text| config.uptane.primary_ecu_serial = text);
    cli.opt_str("uptane-metadata-path").map(|text| config.uptane.metadata_path = text);
    cli.opt_str("uptane-private-key-path").map(|text| config.uptane.private_key_path = text);
    cli.opt_str("uptane-public-key-path").map(|text| config.uptane.public_key_path = text);

    if cli.opt_present("print") {
        exit!(0, "{:#?}", config);
    }

    config
}
