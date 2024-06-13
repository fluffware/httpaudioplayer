extern crate futures;
extern crate hound;
extern crate hyper;
extern crate portaudio;
extern crate tokio;
extern crate triggered;

use core::convert::Infallible;
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{server::Server, Body, Method, Request, Response, StatusCode};
use std::collections::btree_map::BTreeMap;
use std::str::FromStr;
use tokio::select;
use tokio::time::Duration;
use triggered::Trigger;

use futures::future::FutureExt;
use hyper::header;
use std::panic;
use std::sync::{Arc, Mutex};

use konst::{primitive::parse_u32, result::unwrap_ctx};

extern crate nom;

mod split_quoted;
use split_quoted::split_quoted;

mod clip_player;
use clip_player::ClipPlayer;

// Like println! but for errors. Prints to stderr
macro_rules! print_err {
    ($fmt:expr) => {writeln!(&mut std::io::stderr(),
                             $fmt).unwrap()};
    ($fmt:expr, $($arg:tt)*) => {writeln!(&mut std::io::stderr(),
                                          $fmt,
                                          $($arg)*).unwrap()}
}
macro_rules! print_info {
    ($fmt:expr) => {writeln!(&mut std::io::stdout(),
                             $fmt).unwrap()};
    ($fmt:expr, $($arg:tt)*) => {writeln!(&mut std::io::stderr(),
                                          $fmt,
                                          $($arg)*).unwrap()}
}

mod parser {
    extern crate nom;
    use nom::branch::alt;
    use nom::bytes::complete::is_not;
    use nom::bytes::complete::tag;
    use nom::character::complete::char;
    use nom::combinator::eof;
    use nom::combinator::map;
    use nom::multi::separated_list1;
    use nom::sequence::delimited;
    use nom::sequence::preceded;
    use nom::sequence::separated_pair;
    use nom::sequence::terminated;
    use nom::IResult;

    #[derive(Debug)]
    pub enum Request<'a> {
        Read(Vec<&'a [u8]>),
        Write((&'a [u8], &'a [u8])),
    }

    pub fn quoted(input: &[u8]) -> IResult<&[u8], &[u8]> {
        delimited(char('"'), is_not("\""), char('"'))(input)
    }
    pub fn quoted_list(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
        separated_list1(char(','), quoted)(input)
    }

    pub fn read(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
        terminated(preceded(tag("ReadVarNames="), quoted_list), eof)(input)
    }

    pub fn write(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
        separated_pair(
            preceded(tag("WriteVarName="), quoted),
            char('&'),
            preceded(tag("Value="), quoted),
        )(input)
    }
    pub fn request(input: &[u8]) -> IResult<&[u8], Request> {
        alt((map(read, Request::Read), map(write, Request::Write)))(input)
    }
}

fn request_error<M: Into<Body>>(msg: M) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(CONTENT_TYPE, "text/html")
        .body(msg.into())
        .unwrap()
}

pub trait HttpVarOps: Send {
    fn write_var(&mut self, var: &str, value: &str) -> bool;
    fn read_var(&mut self, var: &str) -> Option<String>;
}

fn read_vars(ops: &mut dyn HttpVarOps, vars: &[&[u8]]) -> Response<Body> {
    let vars: Vec<String> = match vars.iter().map(|s| String::from_utf8(s.to_vec())).collect() {
        Ok(v) => v,
        Err(_) => return request_error("Invalid UTF-8 in variable list"),
    };
    let mut body = String::new();
    for v in vars {
        body += &match ops.read_var(&v) {
            Some(s) => "00000110 ".to_string() + &s + "\r\n",
            None => "80000105 ###\r\n".to_string(),
        };
    }
    Response::builder()
        .header(CONTENT_TYPE, "text/fwddata")
        .body(Body::from(body))
        .unwrap()
}

fn write_var(ops: &mut dyn HttpVarOps, var: &[u8], value: &[u8]) -> Response<Body> {
    let value = &String::from_utf8(value.to_vec()).unwrap_or_else(|_| "?".to_string());
    let var = match String::from_utf8(var.to_vec()) {
        Ok(v) => v,
        Err(_) => return request_error("Invalid UTF-8 in write variable name"),
    };

    let body = if ops.write_var(&var, value) {
        "00000000\r\n"
    } else {
        "80000105\r\n"
    };
    Response::builder()
        .header(CONTENT_TYPE, "text/fwddata")
        .body(Body::from(body))
        .unwrap()
}

fn parse_request(ops: &mut dyn HttpVarOps, bytes: Bytes) -> Response<Body> {
    match parser::request(&bytes) {
        nom::IResult::Ok((_, res)) => match res {
            parser::Request::Read(vars) => read_vars(ops, &vars),
            parser::Request::Write((var, value)) => write_var(ops, var, value),
        },
        nom::IResult::Err(err) => request_error(format!("Failed to parse request {}", err)),
    }
}

async fn handle_post(
    ops_arc: Arc<Mutex<dyn HttpVarOps>>,
    mut req: Request<Body>,
) -> Response<Body> {
    let body = req.body_mut();
    let bytes = match hyper::body::to_bytes(body).await {
        Ok(b) => b,
        Err(e) => return request_error(format!("Failed to read POST data: {}", e)),
    };
    let mut ops = ops_arc.lock().unwrap();
    parse_request(&mut *ops, bytes)
}

async fn handle_req(
    ops: Arc<Mutex<dyn HttpVarOps>>,
    req: Request<Body>,
    shutdown: Trigger,
) -> Response<Body> {
    let fut = async {
        let method = req.method();
        let path = req.uri().path();
        match (method, path) {
	    (&Method::GET, "/") => {
                Response::builder()
		    .status(StatusCode::OK)
		    .body(Body::from("This server only accepts POST data at /wwwSiemens conforming to the Simatic HMI HTTP protocol."))
		    .unwrap()
	    },
	    (&Method::POST, "/wwwSiemens") => {
                handle_post(ops, req).await
		},
	    _ => {
                Response::builder()
		    .status(StatusCode::NOT_FOUND)
		    .body(Body::empty())
		    .unwrap()
	    },
        }
    };
    let res = panic::AssertUnwindSafe(fut).catch_unwind().await;
    match res {
        Err(_) => {
            println!("Request handler paniced, shuting down.");
            shutdown.trigger();
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "text/html")
                .body(Body::from("Error in request handler"))
                .unwrap()
        }
        Ok(r) => r,
    }
}

struct AudioOps {
    state: BTreeMap<String, bool>,
    player: ClipPlayer,
    watchdog_start: u64,
    watchdog_timer: u64,
}

impl AudioOps {
    fn new(mut state: BTreeMap<String, bool>, player: ClipPlayer, watchdog_time: u64) -> AudioOps {
        state.insert("WatchdogReset".to_string(), false);
        AudioOps {
            state,
            player,
            watchdog_start: watchdog_time,
            watchdog_timer: watchdog_time,
        }
    }
}

fn play_clip(player: &mut ClipPlayer, clip: &str) {
    match player.play_clip(clip) {
        Ok(_) => {}
        Err(e) => {
            print_err!("Failed to play clip {}: {}", clip, e);
            if let Err(e) =  player.restart() {
                print_err!("Failed to restart audio: {}", e);
            }
        }
    }
}

const SERVER_VERSION: u32 = unwrap_ctx!(parse_u32(env!("CARGO_PKG_VERSION_MAJOR"))) << 24
    | unwrap_ctx!(parse_u32(env!("CARGO_PKG_VERSION_MINOR"))) << 16
    | unwrap_ctx!(parse_u32(env!("CARGO_PKG_VERSION_PATCH")));
impl HttpVarOps for AudioOps {
    fn read_var(&mut self, var: &str) -> Option<String> {
        match var {
            "WatchdogTimer" => Some(self.watchdog_timer.to_string()),
            "ServerVersion" => Some(SERVER_VERSION.to_string()),
            _ => self
                .state
                .get(var)
                .map(|value| (if *value { "1" } else { "0" }).to_string()),
        }
    }

    fn write_var(&mut self, var: &str, value: &str) -> bool {
        match i32::from_str(value) {
            Ok(value) => {
                let var = var.to_string();
                let value = value < 0;
                match self.state.get(&var) {
                    Some(&old) => {
                        if old != value {
                            match var.as_str() {
                                "WatchdogReset" => {
                                    self.watchdog_timer = self.watchdog_start;
                                }
                                _ => play_clip(&mut self.player, &var),
                            }
                        }
                        self.state.insert(var, value);
                        true
                    }
                    None => false,
                }
            }
            Err(_) => false,
        }
    }
}

const SAMPLE_MAX: f64 = i16::MAX as f64;
const SAMPLE_MIN: f64 = i16::MIN as f64;

fn adjust_volume(volume: f64, buffer: &mut [i16]) {
    for s in buffer {
        *s = ((*s as f64) * volume)
            .clamp(SAMPLE_MIN, SAMPLE_MAX)
            .round() as i16;
    }
}

struct Config {
    cmd: String,
    args: Vec<String>,
}

fn read_config(path: &Path) -> std::io::Result<Vec<Config>> {
    let mut conf = Vec::<Config>::new();
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    for line in reader.lines().map_while(Result::ok) {
        let mut tokens = split_quoted(&line);
        if let Some(cmd) = tokens.next() {
            if cmd.starts_with('#') {
                // Comment, ignore
            } else {
                let conf_line = Config {
                    cmd: cmd.to_string(),
                    args: tokens.map(|arg| arg.to_string()).collect::<Vec<String>>(),
                };
                conf.push(conf_line);
            }
        }
    }
    Ok(conf)
}

const DEFAULT_CONFIG_FILE: &str = "httpaudioplayer.conf";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = env::args_os();
    let mut args = args.skip(1);
    let conf_path_str = if let Some(path) = args.next() {
        path
    } else {
        OsStr::new(DEFAULT_CONFIG_FILE).to_os_string()
    };

    print_info!(
        "Starting HTTP audioplayer version {}",
        env!("CARGO_PKG_VERSION")
    );

    let conf = match read_config(Path::new(&conf_path_str)) {
        Err(err) => {
            print_err!(
                "Failed to read configuration file {:?}: {:?}",
                conf_path_str,
                err
            );
            return;
        }
        Ok(c) => c,
    };

    let mut volume = 1.0f64;
    let mut sample_rate: u32 = 44_100;
    let mut channels: u8 = 2;
    let mut bind_addr = "0.0.0.0:8087".parse().unwrap();
    let mut watchdog_timeout: u64 = 0; // seconds, 0 means disabled
    for line in &conf {
        match line.cmd.as_str() {
            "rate" => {
                if line.args.is_empty() {
                    print_err!("Too few arguments for rate");
                    return;
                }
                sample_rate = match u32::from_str(&line.args[0]) {
                    Ok(r) => r,
                    Err(e) => {
                        print_err!("Failed to parse sample rate: {}", e);
                        return;
                    }
                }
            }
            "channels" => {
                if line.args.is_empty() {
                    print_err!("Too few arguments for channels");
                    return;
                }
                channels = match u8::from_str(&line.args[0]) {
                    Ok(r) => r,
                    Err(e) => {
                        print_err!("Failed to parse number of channels: {}", e);
                        return;
                    }
                }
            }
            "bind" => {
                if line.args.is_empty() {
                    print_err!("Too few arguments for rate");
                    return;
                }
                bind_addr = match line.args[0].parse() {
                    Ok(a) => a,
                    Err(e) => {
                        print_err!("Couldn't parse bind address: {}", e);
                        return;
                    }
                }
            }
            "watchdog" => {
                if line.args.is_empty() {
                    print_err!("watchdog commend needs a timeout argument");
                    return;
                }
                watchdog_timeout = match line.args[0].parse() {
                    Ok(a) => a,
                    Err(e) => {
                        print_err!("Couldn't parse watchdog timeout: {}", e);
                        return;
                    }
                }
            }
            &_ => {}
        }
    }

    let mut player = match clip_player::ClipPlayer::new(sample_rate, channels) {
        Ok(s) => s,
        Err(e) => {
            print_err!("Failed to start audio clip player: {}", e);
            return;
        }
    };
    print_info!(
        "Using {} samples/s, {} channels for playback",
        sample_rate,
        channels
    );

    let mut state = BTreeMap::new();

    for line in conf {
        match line.cmd.as_str() {
            "clip" => {
                if line.args.len() < 2 {
                    print_err!("Too few arguments for audio clip");
                    return;
                }
                let slot = &line.args[0];
                let path = Path::new(&line.args[1]);
                match hound::WavReader::open(path) {
                    Ok(mut reader) => {
                        let mut sbuffer = reader
                            .samples::<i16>()
                            .map(|r| r.unwrap())
                            .collect::<Vec<i16>>();

                        #[allow(clippy::float_cmp)]
                        if volume != 1.0 {
                            adjust_volume(volume, &mut sbuffer[..]);
                        }
                        player.add_clip(slot, sbuffer);
                        print_info!(
                            "Loaded clip {} from {} ({} samples/s, {} channels) volume {:.2}",
                            slot,
                            path.to_str().unwrap_or("?"),
                            reader.spec().sample_rate,
                            reader.spec().channels,
                            volume
                        );

                        state.insert(slot.to_string(), false);
                    }
                    Err(err) => {
                        print_err!("Failed to open audio file \"{}\": {}", &line.args[1], err);
                        return;
                    }
                }
            }
            "volume" => {
                if line.args.is_empty() {
                    print_err!("Too few arguments for volume");
                    return;
                }
                volume = match f64::from_str(&line.args[0]) {
                    Ok(r) => r,
                    Err(e) => {
                        print_err!("Failed to parse volume: {}", e);
                        return;
                    }
                }
            }
            "rate" | "bind" | "channels" | "watchdog" => {} // Handled earlier
            c => {
                print_err!("Ignored configuration command '{}'", c);
            }
        }
    }

    let ops = Arc::new(Mutex::new(AudioOps::new(state, player, watchdog_timeout)));

    let (shutdown, wait_shutdown) = triggered::trigger();
    if watchdog_timeout > 0 {
        let shutdown = shutdown.clone();
        let wait_shutdown = wait_shutdown.clone();
        let ops = ops.clone();
        tokio::spawn(async move {
            tokio::pin!(wait_shutdown);
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                select! {
                    _ = wait_shutdown.as_mut() => {
                        break;
                    },
                    _ = tick.tick() => {
                        let mut ops = ops.lock().unwrap();
                        if ops.watchdog_timer == 0 {
                            shutdown.trigger();
                            print_err!("Watchdog timed out");
                            break;
                        }
                        ops.watchdog_timer -= 1;
                    }
                }
            }
        });
    }
    let make_svc = make_service_fn(|_| {
        let ops = ops.clone();
        let shutdown = shutdown.clone();
        async {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let ops = ops.clone();
                let shutdown = shutdown.clone();
                async move { Ok::<_, Infallible>(handle_req(ops, req, shutdown).await) }
            }))
        }
    });
    let server = Server::bind(&bind_addr).serve(make_svc);
    print_info!("Listening on http://{}", server.local_addr());
    let graceful = server.with_graceful_shutdown(wait_shutdown);
    graceful.await.unwrap();
    println!("Server stopped");
}
