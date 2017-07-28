extern crate hyper;
extern crate futures;
extern crate mime;
extern crate portaudio;
extern crate hound;

use std::fs::File;
use std::path::Path;
use std::ffi::OsStr;
use std::io::Write;
use std::error::Error;
use std::io::BufReader;
use std::io::BufRead;
use std::net::AddrParseError;
use std::env;

use futures::future::FutureResult;

use hyper::header::{ContentLength, ContentType};
use hyper::server::{Http, Service, Request, Response};
use hyper::{Method, StatusCode,Chunk};
use mime::Mime;
use std::str::FromStr;
use futures::Stream;
use futures::Future;
use futures::future::Either;
use futures::future::BoxFuture;
use std::collections::btree_map::BTreeMap;

use std::sync::{Arc,Mutex};

#[macro_use]
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
    #[derive(Debug)]
    pub enum Request<'a>
    {
        Read(Vec<&'a[u8]>),
        Write((&'a [u8],&'a [u8]))
    }
    named!(quoted, delimited!(char!('\"'), take_until!("\""), char!('\"')));
    named!(quoted_list <Vec<&[u8]>>, separated_nonempty_list_complete!(char!(','),quoted));
    named!(read <Vec<&[u8]>>, terminated!(preceded!(tag!("ReadVarNames="),quoted_list),eof!()));
    named!(write <(&[u8], &[u8])>, separated_pair!(preceded!(tag!("WriteVarName="),quoted),
                                  char!('&'),
                                  preceded!(tag!("Value="),quoted)));
    named!(pub request <Request>, alt!(map!(read, |v| Request::Read(v)) 
                                       | map!(write, |v| Request::Write(v))));
}

type Ops = Arc<Mutex<HttpVarOps>>;

struct AudioHandler
{
    ops: Ops
}

fn request_error(msg: &str) ->hyper::Response {
    return Response::new()
        .with_status(StatusCode::BadRequest)
        .with_header(ContentType::plaintext())
        .with_header(ContentLength(msg.len() as u64))
        .with_body(msg.to_string())
}

pub trait HttpVarOps : Send {
    fn write_var(&mut self, var: &str, value: &str) -> bool;
    fn read_var(&mut self, var: &str) -> Option<String>;
}

fn read_vars(ops:  &mut HttpVarOps, vars: &Vec<&[u8]>) -> hyper::Response
{
    let vars: Vec<String> = 
        match vars.iter().map(|s| String::from_utf8(s.to_vec())).collect() {
            Ok(v) => v,
            Err(_) => return request_error("Invalid UTF-8 in variable list")
        };
    let mut body = String::new();
    for v in vars {
        body +=
            &match ops.read_var(&v) {
                Some(s) => "00000110 ".to_string()+&s+"\r\n",
                None => "80000105 ###\r\n".to_string()
            };
    }
    Response::new()
        .with_header(ContentType(Mime::from_str("text/fwddata").unwrap()))
        .with_header(ContentLength(body.len() as u64))
        .with_body(body) 
}

fn write_var(ops:  &mut HttpVarOps, var: &[u8], value: &[u8]) -> hyper::Response
{
    let value = &String::from_utf8(value.to_vec()).unwrap_or("?".to_string());
    let var = match String::from_utf8(var.to_vec()) {
            Ok(v) => v,
            Err(_) => return request_error("Invalid UTF-8 in write variable name")
    };

    let body =
        if ops.write_var(&var, &value) {
            "00000000\r\n"
        } else {
            "80000105\r\n"
        };
    Response::new()
        .with_header(ContentType(Mime::from_str("text/fwddata").unwrap()))
        .with_header(ContentLength(body.len() as u64))
        .with_body(body) 
}

fn parse_request(ops: &mut HttpVarOps, chunk: Chunk) -> hyper::Response
{
    let bytes: &[u8] = chunk.as_ref();
    match parser::request(bytes) {
        nom::IResult::Done(_,res) =>{
            //println!("Parsing done");
            match res {
                parser::Request::Read(vars) => {
                    read_vars(ops, &vars)
                },
                parser::Request::Write((var,value)) => {
                    write_var(ops,var,value)
                }
            }
        },
        nom::IResult::Error(err) => {
            request_error(&format!("Failed to parse request {}",
                                  err.description()))
        },

        nom::IResult::Incomplete(_) => {
            request_error("Request to short")
        }
        
    }
        
  
}
    

impl AudioHandler {
    
    fn new(ops: Ops) -> AudioHandler
    {
        AudioHandler{ops: ops}
    }

    fn handle_post(&self, req: Request) -> BoxFuture<hyper::Response, hyper::Error>
    {
        let body = req.body().concat2();
        let ops_arc = self.ops.clone();
        
        body.map(move |chunk| {
            let mut ops = ops_arc.lock().unwrap();
            parse_request(&mut *ops, chunk)
        }).boxed()
    }
}

impl Service for AudioHandler
{
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Either<FutureResult<Self::Response, Self::Error>,
                         BoxFuture<Self::Response, Self::Error>
                         >;

    fn call(&self, req: Request) -> Self::Future {
         match (req.method(), req.path()) {
            (&Method::Get, "/") => {
                Either::A(futures::future::ok(
                    Response::new().with_body("This server only accepts POST data at /wwwSiemens conforming to the Simatic HMI HTTP protocol.")))
            },
             (&Method::Post, "/wwwSiemens") => {
                 
                 Either::B(self.handle_post(req))
             },
            _ => {
                Either::A(futures::future::ok(
                    Response::new().with_status(StatusCode::NotFound)))
            },
        }

    }
}

struct AudioOps {
    state: BTreeMap<String, bool>,
    player: ClipPlayer
}

impl HttpVarOps for AudioOps
{
    fn read_var(&mut self, var: &str) ->Option<String> {
        match self.state.get(var) {
            Some(&value) => Some((if value {"1"} else {"0"}).to_string()),
            None => None
        }
    }
    fn write_var(&mut self, var: &str, value: &str) ->bool
    {
        
        match i32::from_str(&value) {
            Ok(value) => {
                let var = var.to_string();
                let value = value < 0;
                match self.state.get(&var) {
                    Some(&old) => {
                        if old != value {
                            println!("Changed: {}", var);
                            match self.player.play_clip(&var) {
                                Ok(_) => {},
                                Err(e) => {
                                    print_err!("Failed to play clip {}: {}",
                                             var, e.description());
                                }
                            }
                                
                        }
                        self.state.insert(var,value);
                        true
                    },
                    None => false
                }
            },
            Err(_) => false
        }
    }
}

struct Config
{
    cmd: String,
    args: Vec<String>
}

fn read_config(path: &Path) -> std::io::Result<Vec<Config>>
{
    let mut conf = Vec::<Config>::new();
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    for line_res in  reader.lines() {
        if let Ok(line) = line_res {
            let mut tokens = split_quoted(&line);
            if let Some(cmd) = tokens.next() {
                if cmd.starts_with("#") {
                    // Comment, ignore
                } else {
                    let conf_line = 
                        Config{cmd: cmd.to_string(), 
                               args: tokens.map(|arg| arg.to_string()).collect::<Vec<String>>()};
                    conf.push(conf_line);
                }
            }   
        }
    }
    Ok(conf)
}

const DEFAULT_CONFIG_FILE: &'static str = "httpaudioplayer.conf";

fn main() {
    let args = env::args_os();
    let mut args = args.skip(1);
    let conf_path_str = 
        if let Some(path) = args.next() {
            path
        } else {
            OsStr::new(DEFAULT_CONFIG_FILE).to_os_string()
        };
    let conf =
        match read_config(Path::new(&conf_path_str)) {
            Err(err) => {
                print_err!("Failed to read configuration file {:?}: {:?}", conf_path_str, err.description());
                return
            },
            Ok(c) => c
        };

    let mut sample_rate:u32 = 44_100;
    let mut channels:u8 = 2;
    let mut bind_addr = "0.0.0.0:8087".parse().unwrap();

    for line in &conf {
        match line.cmd.as_str() {
            "rate" => { 
                if line.args.len() < 1 {
                    print_err!("Too few arguments for rate");
                    return
                }
                sample_rate = match u32::from_str(&line.args[0]) {
                    Ok(r) => r,
                    Err(e) => {
                        print_err!("Failed to parse sample rate: {}",
                                   e.description());
                        return
                    }
                }
            },
            "channels" => {
                if line.args.len() < 1 {
                    print_err!("Too few arguments for channels");
                    return
                }
                channels = match u8::from_str(&line.args[0]) {
                    Ok(r) => r,
                    Err(e) => {
                        print_err!("Failed to parse number of channels: {}",
                                   e.description());
                        return
                    }
                }
            },
            "bind" => {
                if line.args.len() < 1 {
                    print_err!("Too few arguments for rate");
                    return
                }
                bind_addr = match line.args[0].parse() {
                    Ok(a) => a,
                    Err(e) => {
                        print_err!("Couldn't parse bind address: {}", 
                                   (e as AddrParseError).description());
                        return
                    }
                }
            },
            &_ => {}
        }
    }
    let mut player = match clip_player::ClipPlayer::new(sample_rate,channels) {
         Ok(s) => s,
            Err(e) => {
                print_err!("Failed to start audio clip player: {}", 
                           e.description());
                return;
            }
    };
    print_info!("Using {} samples/s, {} channels for playback", 
               sample_rate, channels);
    for line in conf {
        match line.cmd.as_str() {
            "clip" => {
                if line.args.len() < 2 {
                    print_err!("Too few arguments for audio clip");
                    return
                }
                let slot = &line.args[0];
                let path = Path::new(&line.args[1]);
                match hound::WavReader::open(path) {
                    Ok(mut reader) => {
                        let sbuffer = reader.samples::<i16>()
                            .map(|r| {r.unwrap()}).collect::<Vec<i16>>();
                        player.add_clip(slot, sbuffer);
                        print_info!("Loaded clip {} from {} ({} samples/s, {} channels)",
                                    slot, path.to_str().unwrap_or("?"), reader.spec().sample_rate, reader.spec().channels);
                        
                    },
                    Err(err) => {
                        print_err!("Failed to open audio file \"{}\": {}",
                                   &line.args[1], err.description());
                        return
                    }
                }
    
            },
            
            "rate" | "bind" => {}, // Handled earlier
            c => {print_err!("Ignored configuration command '{}'", c);}
        }
        //println!("Cmd: {}", line.cmd);
    }

    let ops = Arc::new(Mutex::new(AudioOps{state: BTreeMap::new(), player: player}));
    {
        let tree = &mut ops.lock().unwrap().state;
        tree.insert("Alarm".to_string(), false);
        tree.insert("Info".to_string(), true);
        tree.insert("Inc".to_string(), true);
        tree.insert("Dec".to_string(), false);
        tree.insert("Accept".to_string(), true);
        tree.insert("Exe".to_string(), false);
    }

    let server = Http::new().bind(&bind_addr, move || Ok(AudioHandler::new(ops.clone()))).unwrap();
    print_info!("Listening on http://{}", server.local_addr().unwrap());
    server.run().unwrap();
}
