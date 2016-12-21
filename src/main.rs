#[macro_use] extern crate chan;
extern crate chan_signal;
extern crate crossbeam;
extern crate env_logger;
extern crate getopts;
extern crate hyper;
#[macro_use] extern crate log;
extern crate rustc_serialize;
#[macro_use] extern crate sota;
extern crate time;

use chan::{Sender, Receiver, WaitGroup};
use chan_signal::Signal;
use env_logger::LogBuilder;
use getopts::Options;
use log::{LogLevelFilter, LogRecord};
use std::{env, process, thread};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::ops::Deref;
use std::time::Duration;

use sota::datatype::{Command, Config, Event};
use sota::gateway::{Console, DBus, Gateway, Interpret, Http, Socket, Websocket};
use sota::broadcast::Broadcast;
use sota::http::{AuthClient, set_certificates};
use sota::interpreter::{EventInterpreter, CommandInterpreter, Interpreter, GlobalInterpreter};
use sota::rvi::{Edge, Services};


macro_rules! exit {
    ($code:expr, $fmt:expr, $($arg:tt)*) => {{
        print!(concat!($fmt, "\n"), $($arg)*);
        process::exit($code);
    }}
}


fn main() {
    let version = start_logging();
    let config  = build_config(&version);

    set_certificates(config.device.certificates_path.as_ref().map(Deref::deref),
                     config.device.p12_path.as_ref().map(Deref::deref),
                     &config.device.p12_password);

    let (etx, erx) = chan::async::<Event>();
    let (ctx, crx) = chan::async::<Command>();
    let (itx, irx) = chan::async::<Interpret>();

    let mut broadcast = Broadcast::new(erx);
    let wg = WaitGroup::new();

    ctx.send(Command::Authenticate(None));

    crossbeam::scope(|scope| {
        // subscribe to signals first
        let signals = chan_signal::notify(&[Signal::INT, Signal::TERM]);
        scope.spawn(move || start_signal_handler(signals));

        if config.core.polling {
            let poll_tick = config.core.polling_sec;
            let poll_itx  = itx.clone();
            let poll_wg   = wg.clone();
            scope.spawn(move || start_update_poller(poll_tick, poll_itx, poll_wg));
        }

        //
        // start gateways
        //

        if config.gateway.console {
            let cons_itx = itx.clone();
            let cons_sub = broadcast.subscribe();
            scope.spawn(move || Console.start(cons_itx, cons_sub));
        }

        if config.gateway.dbus {
            let dbus_itx = itx.clone();
            let dbus_sub = broadcast.subscribe();
            let mut dbus = DBus { dbus_cfg: config.dbus.clone(), itx: itx.clone() };
            scope.spawn(move || dbus.start(dbus_itx, dbus_sub));
        }

        if config.gateway.http {
            let http_itx = itx.clone();
            let http_sub = broadcast.subscribe();
            let mut http = Http { server: *config.network.http_server };
            scope.spawn(move || http.start(http_itx, http_sub));
        }

        let rvi_services = if config.gateway.rvi {
            let rvi_edge = config.network.rvi_edge_server.clone();
            let services = Services::new(config.rvi.clone(), config.device.uuid.clone(), etx.clone());
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
                commands_path: config.network.socket_commands_path.clone(),
                events_path:   config.network.socket_events_path.clone()
            };
            scope.spawn(move || socket.start(socket_itx, socket_sub));
        }

        if config.gateway.websocket {
            let ws_server = config.network.websocket_server.clone();
            let ws_itx    = itx.clone();
            let ws_sub    = broadcast.subscribe();
            let mut ws    = Websocket { server: ws_server, clients: Arc::new(Mutex::new(HashMap::new())) };
            scope.spawn(move || ws.start(ws_itx, ws_sub));
        }

        //
        // start interpreters
        //

        let event_sub = broadcast.subscribe();
        let event_ctx = ctx.clone();
        let event_mgr = config.device.package_manager.clone();
        let event_dl  = config.device.auto_download.clone();
        let event_sys = config.device.system_info.clone();
        let event_wg  = wg.clone();
        scope.spawn(move || EventInterpreter {
            pacman:        event_mgr,
            auto_download: event_dl,
            sysinfo:       event_sys,
        }.run(event_sub, event_ctx, event_wg));

        let cmd_itx = itx.clone();
        let cmd_wg  = wg.clone();
        scope.spawn(move || CommandInterpreter.run(crx, cmd_itx, cmd_wg));

        scope.spawn(move || GlobalInterpreter {
            config:      config,
            token:       None,
            http_client: Box::new(AuthClient::default()),
            rvi:         rvi_services,
        }.run(irx, etx, wg));

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
    builder.parse(&env::var("RUST_LOG").unwrap_or("INFO".to_string()));
    builder.init().expect("builder already initialized");

    version.to_string()
}

fn start_signal_handler(signals: Receiver<Signal>) {
    loop {
        match signals.recv() {
            Some(Signal::INT) | Some(Signal::TERM) => process::exit(0),
            _ => ()
        }
    }
}

fn start_update_poller(interval: u64, itx: Sender<Interpret>, wg: WaitGroup) {
    info!("Polling for new updates every {} seconds.", interval);
    let (etx, erx) = chan::async::<Event>();
    let wait = Duration::from_secs(interval);
    loop {
        wg.wait();           // wait until not busy
        thread::sleep(wait); // then wait `interval` seconds
        itx.send(Interpret {
            command:     Command::GetUpdateRequests,
            response_tx: Some(Arc::new(Mutex::new(etx.clone())))
        });                  // then request new updates
        let _ = erx.recv();  // then wait for the response
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
    opts.optopt("", "auth-credentials-file", "change the auth credentials file", "PATH");

    opts.optopt("", "core-server", "change the core server", "URL");
    opts.optopt("", "core-polling", "toggle polling the core server for updates", "BOOL");
    opts.optopt("", "core-polling-sec", "change the core polling interval", "SECONDS");

    opts.optopt("", "dbus-name", "change the dbus registration name", "NAME");
    opts.optopt("", "dbus-path", "change the dbus path", "PATH");
    opts.optopt("", "dbus-interface", "change the dbus interface name", "INTERFACE");
    opts.optopt("", "dbus-software-manager", "change the dbus software manager name", "NAME");
    opts.optopt("", "dbus-software-manager-path", "change the dbus software manager path", "PATH");
    opts.optopt("", "dbus-timeout", "change the dbus installation timeout", "TIMEOUT");

    opts.optopt("", "device-uuid", "change the device uuid", "UUID");
    opts.optopt("", "device-packages-dir", "change downloaded directory for packages", "PATH");
    opts.optopt("", "device-package-manager", "change the package manager", "MANAGER");
    opts.optopt("", "device-certificates-path", "change the CA certificates path", "PATH");
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

    let matches = opts.parse(&args[1..]).unwrap_or_else(|err| panic!(err.to_string()));

    if matches.opt_present("help") {
        exit!(0, "{}", opts.usage(&format!("Usage: {} [options]", program)));
    } else if matches.opt_present("version") {
        exit!(0, "{}", version);
    }

    let mut config = match matches.opt_str("config").or(env::var("SOTA_CONFIG").ok()) {
        Some(file) => Config::load(&file).unwrap_or_else(|err| exit!(1, "{}", err)),
        None => {
            warn!("No config file given. Falling back to defaults.");
            Config::default()
        }
    };

    config.auth.as_mut().map(|auth_cfg| {
        matches.opt_str("auth-client-id").map(|id| auth_cfg.client_id = id);
        matches.opt_str("auth-client-secret").map(|secret| auth_cfg.client_secret = secret);
        matches.opt_str("auth-server").map(|text| {
            auth_cfg.server = text.parse().unwrap_or_else(|err| exit!(1, "Invalid auth-server URL: {}", err));
        });
    });

    matches.opt_str("core-server").map(|text| {
        config.core.server = text.parse().unwrap_or_else(|err| exit!(1, "Invalid core-server URL: {}", err));
    });
    matches.opt_str("core-polling").map(|polling| {
        config.core.polling = polling.parse().unwrap_or_else(|err| exit!(1, "Invalid core-polling boolean: {}", err));
    });
    matches.opt_str("core-polling-sec").map(|secs| {
        config.core.polling_sec = secs.parse().unwrap_or_else(|err| exit!(1, "Invalid core-polling-sec: {}", err));
    });

    matches.opt_str("dbus-name").map(|name| config.dbus.name = name);
    matches.opt_str("dbus-path").map(|path| config.dbus.path = path);
    matches.opt_str("dbus-interface").map(|interface| config.dbus.interface = interface);
    matches.opt_str("dbus-software-manager").map(|mgr| config.dbus.software_manager = mgr);
    matches.opt_str("dbus-software-manager-path").map(|mgr_path| config.dbus.software_manager_path = mgr_path);
    matches.opt_str("dbus-timeout").map(|timeout| {
        config.dbus.timeout = timeout.parse().unwrap_or_else(|err| exit!(1, "Invalid dbus-timeout: {}", err));
    });

    matches.opt_str("device-uuid").map(|uuid| config.device.uuid = uuid);
    matches.opt_str("device-packages-dir").map(|path| config.device.packages_dir = path);
    matches.opt_str("device-package-manager").map(|text| {
        config.device.package_manager = text.parse().unwrap_or_else(|err| exit!(1, "Invalid device-package-manager: {}", err));
    });
    matches.opt_str("device-certificates-path").map(|path| config.device.certificates_path = Some(path));
    matches.opt_str("device-p12-path").map(|path| config.device.p12_path = Some(path));
    matches.opt_str("device-p12-password").map(|pw| config.device.p12_password = pw);
    matches.opt_str("device-system-info").map(|cmd| config.device.system_info = Some(cmd));

    matches.opt_str("gateway-console").map(|console| {
        config.gateway.console = console.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-console boolean: {}", err));
    });
    matches.opt_str("gateway-dbus").map(|dbus| {
        config.gateway.dbus = dbus.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-dbus boolean: {}", err));
    });
    matches.opt_str("gateway-http").map(|http| {
        config.gateway.http = http.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-http boolean: {}", err));
    });
    matches.opt_str("gateway-rvi").map(|rvi| {
        config.gateway.rvi = rvi.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-rvi boolean: {}", err));
    });
    matches.opt_str("gateway-socket").map(|socket| {
        config.gateway.socket = socket.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-socket boolean: {}", err));
    });
    matches.opt_str("gateway-websocket").map(|websocket| {
        config.gateway.websocket = websocket.parse().unwrap_or_else(|err| exit!(1, "Invalid gateway-websocket boolean: {}", err));
    });

    matches.opt_str("network-http-server").map(|addr| {
        config.network.http_server = addr.parse().unwrap_or_else(|err| exit!(1, "Invalid network-http-server: {}", err));
    });
    matches.opt_str("network-rvi-edge-server").map(|addr| {
        config.network.rvi_edge_server = addr.parse().unwrap_or_else(|err| exit!(1, "Invalid network-rvi-edge-server: {}", err));
    });
    matches.opt_str("network-socket-commands-path").map(|path| config.network.socket_commands_path = path);
    matches.opt_str("network-socket-events-path").map(|path| config.network.socket_events_path = path);
    matches.opt_str("network-websocket-server").map(|server| config.network.websocket_server = server);

    matches.opt_str("rvi-client").map(|url| {
        config.rvi.client = url.parse().unwrap_or_else(|err| exit!(1, "Invalid rvi-client URL: {}", err));
    });
    matches.opt_str("rvi-storage-dir").map(|dir| config.rvi.storage_dir = dir);
    matches.opt_str("rvi-timeout").map(|timeout| {
        config.rvi.timeout = Some(timeout.parse().unwrap_or_else(|err| exit!(1, "Invalid rvi-timeout: {}", err)));
    });

    if matches.opt_present("print") {
        exit!(0, "{:#?}", config);
    }

    config
}
