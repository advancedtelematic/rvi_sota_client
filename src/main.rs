#[macro_use] extern crate chan;
extern crate chan_signal;
extern crate crossbeam;
extern crate env_logger;
extern crate getopts;
extern crate hyper;
#[macro_use] extern crate libotaplus;
#[macro_use] extern crate log;
extern crate rustc_serialize;
extern crate time;

use chan::{Sender, Receiver};
use chan_signal::Signal;
use env_logger::LogBuilder;
use getopts::Options;
use log::{LogLevelFilter, LogRecord};
use std::env;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libotaplus::datatype::{Command, Config, Event, SystemInfo};
use libotaplus::gateway::{Console, DBus, Gateway, Interpret, Http, Websocket};
use libotaplus::gateway::broadcast::Broadcast;
use libotaplus::http::{AuthClient, set_ca_certificates};
use libotaplus::interpreter::{EventInterpreter, CommandInterpreter, Interpreter, GlobalInterpreter};
use libotaplus::rvi::{Edge, Services};


macro_rules! exit {
    ($fmt:expr, $($arg:tt)*) => {{
        print!(concat!($fmt, "\n"), $($arg)*);
        std::process::exit(1);
    }}
}


fn start_signal_handler(signals: Receiver<Signal>) {
    loop {
        match signals.recv() {
            Some(Signal::INT) | Some(Signal::TERM) => std::process::exit(0),
            _ => ()
        }
    }
}

fn start_update_poller(interval: u64, itx: Sender<Interpret>) {
    let (etx, erx) = chan::async::<Event>();
    let tick       = chan::tick(Duration::from_secs(interval));
    loop {
        let _ = tick.recv();
        itx.send(Interpret {
            command:     Command::GetPendingUpdates,
            response_tx: Some(Arc::new(Mutex::new(etx.clone())))
        });
        let _ = erx.recv();
    }
}

fn perform_initial_sync(ctx: &Sender<Command>) {
    ctx.send(Command::Authenticate(None));
    ctx.send(Command::UpdateInstalledPackages);
    ctx.send(Command::SendSystemInfo);
}

fn main() {
    setup_logging();

    let config = build_config();
    set_ca_certificates(Path::new(&config.device.certificates_path));

    let (etx, erx) = chan::async::<Event>();
    let (ctx, crx) = chan::async::<Command>();
    let (itx, irx) = chan::async::<Interpret>();

    let mut broadcast = Broadcast::new(erx);
    perform_initial_sync(&ctx);

    crossbeam::scope(|scope| {
        // Must subscribe to the signal before spawning ANY other threads
        let signals = chan_signal::notify(&[Signal::INT, Signal::TERM]);
        scope.spawn(move || start_signal_handler(signals));

        let poll_tick = config.device.polling_interval;
        let poll_itx  = itx.clone();
        scope.spawn(move || start_update_poller(poll_tick, poll_itx));

        if config.gateway.console {
            let cons_itx = itx.clone();
            let cons_sub = broadcast.subscribe();
            scope.spawn(move || Console.start(cons_itx, cons_sub));
        }

        let mut rvi = None;
        if config.gateway.dbus {
            let rvi_cfg  = config.rvi.as_ref().unwrap_or_else(|| exit!("{}", "rvi config required for dbus gateway"));
            let services = Services::new(rvi_cfg.clone(), config.device.uuid.clone(), etx.clone());
            let mut edge = Edge::new(services.clone(), rvi_cfg.edge.clone(), rvi_cfg.client.clone());
            scope.spawn(move || edge.start());
            rvi = Some(services);

            let dbus_cfg = config.dbus.as_ref().unwrap_or_else(|| exit!("{}", "dbus config required for dbus gateway"));
            let dbus_itx = itx.clone();
            let dbus_sub = broadcast.subscribe();
            let mut dbus = DBus { dbus_cfg: dbus_cfg.clone(), itx: itx.clone() };
            scope.spawn(move || dbus.start(dbus_itx, dbus_sub));
        }

        if config.gateway.http {
            let http_itx = itx.clone();
            let http_sub = broadcast.subscribe();
            scope.spawn(move || Http.start(http_itx, http_sub));
        }

        if config.gateway.websocket {
            let ws_itx = itx.clone();
            let ws_sub = broadcast.subscribe();
            let mut ws = Websocket { clients: Arc::new(Mutex::new(HashMap::new())) };
            scope.spawn(move || ws.start(ws_itx, ws_sub));
        }

        let event_sub = broadcast.subscribe();
        let event_ctx = ctx.clone();
        scope.spawn(move || EventInterpreter.run(event_sub, event_ctx));

        let cmd_itx = itx.clone();
        scope.spawn(move || CommandInterpreter.run(crx, cmd_itx));

        scope.spawn(move || GlobalInterpreter {
            config:      config,
            token:       None,
            http_client: Box::new(AuthClient::default()),
            rvi:         rvi,
            loopback_tx: itx,
        }.run(irx, etx));

        scope.spawn(move || broadcast.start());
    });
}

fn setup_logging() {
    let version     = option_env!("SOTA_VERSION").unwrap_or("?");
    let mut builder = LogBuilder::new();
    builder.format(move |record: &LogRecord| {
        let timestamp = format!("{}", time::now_utc().rfc3339());
        format!("{} ({}): {} - {}", timestamp, version, record.level(), record.args())
    });
    builder.filter(Some("hyper"), LogLevelFilter::Info);

    let _ = env::var("RUST_LOG").map(|level| builder.parse(&level));
    builder.init().expect("env_logger::init() called twice, blame the programmers.");
}

fn build_config() -> Config {
    let args     = env::args().collect::<Vec<String>>();
    let program  = args[0].clone();
    let mut opts = Options::new();

    opts.optflag("h", "help", "print this help menu");
    opts.optopt("", "config", "change config path", "PATH");

    opts.optopt("", "auth-server", "change the auth server", "URL");
    opts.optopt("", "auth-client-id", "change the auth client id", "ID");
    opts.optopt("", "auth-secret", "change the auth secret", "SECRET");
    opts.optopt("", "auth-credentials-file", "change the auth credentials file", "PATH");

    opts.optopt("", "core-server", "change the core server", "URL");

    opts.optopt("", "dbus-name", "change the dbus registration name", "NAME");
    opts.optopt("", "dbus-path", "change the dbus path", "PATH");
    opts.optopt("", "dbus-interface", "change the dbus interface name", "INTERFACE");
    opts.optopt("", "dbus-software-manager", "change the dbus software manager name", "NAME");
    opts.optopt("", "dbus-software-manager-path", "change the dbus software manager path", "PATH");
    opts.optopt("", "dbus-timeout", "change the dbus installation timeout", "TIMEOUT");

    opts.optopt("", "device-uuid", "change the device uuid", "UUID");
    opts.optopt("", "device-vin", "change the device vin", "VIN");
    opts.optopt("", "device-packages-dir", "change downloaded directory for packages", "PATH");
    opts.optopt("", "device-package-manager", "change the package manager", "MANAGER");
    opts.optopt("", "device-polling-interval", "change the package polling interval", "INTERVAL");
    opts.optopt("", "device-certificates-path", "change the OpenSSL CA certificates file", "PATH");
    opts.optopt("", "device-system-info", "change the system information command", "PATH");

    opts.optopt("", "gateway-console", "toggle the console gateway", "BOOL");
    opts.optopt("", "gateway-dbus", "toggle the dbus gateway", "BOOL");
    opts.optopt("", "gateway-http", "toggle the http gateway", "BOOL");
    opts.optopt("", "gateway-websocket", "toggle the websocket gateway", "BOOL");

    opts.optopt("", "rvi-client", "change the rvi client URL", "URL");
    opts.optopt("", "rvi-edge", "change the exposed rvi edge URL", "URL");
    opts.optopt("", "rvi-storage-dir", "change the rvi storage directory", "PATH");
    opts.optopt("", "rvi-timeout", "change the rvi timeout", "TIMEOUT");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|err| panic!(err.to_string()));
    if matches.opt_present("h") {
        exit!("{}", opts.usage(&format!("Usage: {} [options]", program)));
    }

    let config_file = matches.opt_str("config").unwrap_or_else(|| {
        env::var("SOTA_CONFIG").unwrap_or_else(|_| exit!("{}", "No config file provided."))
    });
    let mut config  = Config::load(&config_file).unwrap_or_else(|err| exit!("{}", err));

    config.auth.as_mut().map(|auth_cfg| {
        matches.opt_str("auth-client-id").map(|id| auth_cfg.client_id = id);
        matches.opt_str("auth-secret").map(|secret| auth_cfg.secret = secret);
        matches.opt_str("auth-server").map(|text| {
            auth_cfg.server = text.parse().unwrap_or_else(|err| exit!("Invalid auth-server URL: {}", err));
        });
    });

    matches.opt_str("core-server").map(|text| {
        config.core.server = text.parse().unwrap_or_else(|err| exit!("Invalid core-server URL: {}", err));
    });

    config.dbus.as_mut().map(|dbus_cfg| {
        matches.opt_str("dbus-name").map(|name| dbus_cfg.name = name);
        matches.opt_str("dbus-path").map(|path| dbus_cfg.path = path);
        matches.opt_str("dbus-interface").map(|interface| dbus_cfg.interface = interface);
        matches.opt_str("dbus-software-manager").map(|mgr| dbus_cfg.software_manager = mgr);
        matches.opt_str("dbus-software-manager-path").map(|mgr_path| dbus_cfg.software_manager_path = mgr_path);
        matches.opt_str("dbus-timeout").map(|timeout| {
            dbus_cfg.timeout = timeout.parse().unwrap_or_else(|err| exit!("Invalid dbus timeout: {}", err));
        });
    });

    matches.opt_str("device-uuid").map(|uuid| config.device.uuid = uuid);
    matches.opt_str("device-vin").map(|vin| config.device.vin = vin);
    matches.opt_str("device-packages-dir").map(|path| config.device.packages_dir = path);
    matches.opt_str("device-package-manager").map(|text| {
        config.device.package_manager = text.parse().unwrap_or_else(|err| exit!("Invalid device package manager: {}", err));
    });
    matches.opt_str("device-polling-interval").map(|interval| {
        config.device.polling_interval = interval.parse().unwrap_or_else(|err| exit!("Invalid device polling interval: {}", err));
    });
    matches.opt_str("device-certificates-path").map(|certs| config.device.certificates_path = certs);
    matches.opt_str("device-system-info").map(|cmd| config.device.system_info = SystemInfo::new(cmd));

    matches.opt_str("gateway-console").map(|console| {
        config.gateway.console = console.parse().unwrap_or_else(|err| exit!("Invalid console gateway boolean: {}", err));
    });
    matches.opt_str("gateway-dbus").map(|dbus| {
        config.gateway.dbus = dbus.parse().unwrap_or_else(|err| exit!("Invalid dbus gateway boolean: {}", err));
    });
    matches.opt_str("gateway-http").map(|http| {
        config.gateway.http = http.parse().unwrap_or_else(|err| exit!("Invalid http gateway boolean: {}", err));
    });
    matches.opt_str("gateway-websocket").map(|websocket| {
        config.gateway.websocket = websocket.parse().unwrap_or_else(|err| exit!("Invalid websocket gateway boolean: {}", err));
    });

    config.rvi.as_mut().map(|rvi_cfg| {
        matches.opt_str("rvi-client").map(|url| {
            rvi_cfg.client = url.parse().unwrap_or_else(|err| exit!("Invalid rvi-client URL: {}", err));
        });
        matches.opt_str("rvi-edge").map(|url| {
            rvi_cfg.edge = url.parse().unwrap_or_else(|err| exit!("Invalid rvi-edge: {}", err));
        });
        matches.opt_str("rvi-storage-dir").map(|dir| rvi_cfg.storage_dir = dir);
        matches.opt_str("rvi-timeout").map(|timeout| {
            rvi_cfg.timeout = Some(timeout.parse().unwrap_or_else(|err| exit!("Invalid rvi timeout: {}", err)));
        });
    });

    config
}
