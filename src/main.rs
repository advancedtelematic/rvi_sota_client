extern crate chan;
extern crate chan_signal;
extern crate crossbeam;
extern crate env_logger;
extern crate getopts;
extern crate hyper;
#[macro_use] extern crate log;
extern crate sota;
extern crate time;

use chan::{Sender, Receiver};
use chan_signal::Signal;
use env_logger::LogBuilder;
use getopts::Options;
use log::{LogLevelFilter, LogRecord};
use std::{env, process, thread};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sota::datatype::{Command, Config, Event};
use sota::gateway::{Console, DBus, Gateway, Interpret, Http, Socket, Websocket};
use sota::broadcast::Broadcast;
use sota::http::{AuthClient, TlsClient};
use sota::interpreter::{CommandInterpreter, EventInterpreter, IntermediateInterpreter, Interpreter};
use sota::pacman::PacMan;
use sota::rvi::{Edge, Services};
use sota::uptane::{Service, Uptane};


macro_rules! exit {
    ($code:expr, $fmt:expr, $($arg:tt)*) => {{
        println!($fmt, $($arg)*);
        process::exit($code);
    }}
}


fn main() {
    let version = start_logging();
    let config  = build_config(&version);

    TlsClient::init(config.tls_data());
    let auth = config.initial_auth().unwrap_or_else(|err| exit!(2, "{}", err));
    let http = AuthClient::from(auth.clone());

    let (etx, erx) = chan::async::<Event>();
    let (ctx, crx) = chan::async::<Command>();
    let (itx, irx) = chan::async::<Interpret>();
    let mut broadcast = Broadcast::new(erx);

    crossbeam::scope(|scope| {
        let signals = chan_signal::notify(&[Signal::INT, Signal::TERM]);
        scope.spawn(move || start_signal_handler(&signals));

        if config.core.polling {
            let poll_tick = config.core.polling_sec;
            let poll_itx  = itx.clone();
            scope.spawn(move || start_update_poller(poll_tick, &poll_itx));
        }

        if config.gateway.console {
            let cons_itx = itx.clone();
            let cons_sub = broadcast.subscribe();
            scope.spawn(move || Console.start(cons_itx, cons_sub));
        }

        if config.gateway.dbus {
            let dbus_itx = itx.clone();
            let dbus_sub = broadcast.subscribe();
            let mut dbus = DBus { cfg: config.dbus.clone() };
            scope.spawn(move || dbus.start(dbus_itx, dbus_sub));
        }

        if config.gateway.http {
            let http_itx = itx.clone();
            let http_sub = broadcast.subscribe();
            let mut http = Http { server: *config.network.http_server };
            scope.spawn(move || http.start(http_itx, http_sub));
        }

        let services = if config.gateway.rvi {
            let rvi_edge = config.network.rvi_edge_server.clone();
            let services = Services::new(config.rvi.clone(), format!("{}", config.device.uuid), etx.clone());
            let mut edge = Edge::new(services.clone(), rvi_edge, config.rvi.client.clone());
            scope.spawn(move || edge.start());
            Some(services)
        } else {
            None
        };

        if config.gateway.socket {
            let socket_itx = itx.clone();
            let socket_sub = broadcast.subscribe();
            let mut socket = Socket {
                cmd_sock: config.network.socket_commands_path.clone(),
                ev_sock:  config.network.socket_events_path.clone()
            };
            scope.spawn(move || socket.start(socket_itx, socket_sub));
        }

        if config.gateway.websocket {
            let ws_itx = itx.clone();
            let ws_sub = broadcast.subscribe();
            let mut ws = Websocket { server: config.network.websocket_server.clone() };
            scope.spawn(move || ws.start(ws_itx, ws_sub));
        }

        let uptane = if let PacMan::Uptane = config.device.package_manager {
            if services.is_some() { exit!(2, "{}", "unexpected [rvi] config with uptane package manager"); }
            let mut uptane = Uptane::new(&config).unwrap_or_else(|err| exit!(2, "couldn't start uptane: {}", err));
            let _ = uptane.get_root(&http, &Service::Director).map_err(|err| exit!(2, "couldn't get root.json from director: {}", err));
            Some(uptane)
        } else {
            None
        };

        let ei_sub  = broadcast.subscribe();
        let ei_ctx  = ctx.clone();
        let ei_loop = etx.clone();
        let ei_auth = auth.clone();
        let ei_mgr  = config.device.package_manager.clone();
        let ei_dl   = config.device.auto_download;
        let ei_sys  = config.device.system_info.clone();
        let ei_tree = config.tls.as_ref().map_or(None, |tls| Some(tls.server.join("/treehub")));
        scope.spawn(move || EventInterpreter {
            loop_tx: ei_loop,
            auth:    ei_auth,
            pacman:  ei_mgr,
            auto_dl: ei_dl,
            sysinfo: ei_sys,
            treehub: ei_tree,
        }.run(ei_sub, ei_ctx));

        scope.spawn(move || IntermediateInterpreter::default().run(crx, itx));

        scope.spawn(move || CommandInterpreter {
            config: config,
            auth:   auth,
            http:   Box::new(http),
            rvi:    services,
            uptane: uptane,
        }.run(irx, etx));

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

fn start_update_poller(interval: u64, itx: &Sender<Interpret>) {
    info!("Polling for new updates every {} seconds.", interval);
    let (etx, erx) = chan::async::<Event>();
    let etx = Arc::new(Mutex::new(etx));
    loop {
        itx.send(Interpret { cmd: Command::GetUpdateRequests, etx: Some(etx.clone()) });
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
