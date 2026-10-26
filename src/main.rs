//! pasiv-rx: Pasiv's own RandomX CPU miner.
//!
//! A drop-in for the slice of XMRig that Pasiv uses — the same command line
//! (pool blocks `-o … -u … -p … -k --tls -a …`, `-c`, `-t`, `--retries`), the
//! same local API (see `api`), and log lines worded so Pasiv's supervisor
//! classifiers read them unchanged. Built and signed by Pasiv so the Windows
//! CPU lane needs no Defender exclusion and no UAC prompt: stock XMRig, even
//! Pasiv-signed, is quarantined on write (2026-10-24).
//!
//!   pasiv-rx -c runtime.json -o host:port -u LOGIN -p x -k [--tls] [-o …] -t N --retries 1
//!   pasiv-rx --bench [-t N] [--seconds S]
mod api;
mod net;
mod rx;

use rx::Shared;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NONCE_AT: usize = 39;
const BATCH: u32 = 256;

/// One line on stdout, XMRig-style: a fixed-width tag, then the message.
pub fn log(tag: &str, msg: &str) {
    println!("{tag:<8} {msg}");
}

#[derive(Clone, Debug)]
pub struct Pool {
    pub endpoint: net::Endpoint,
    pub user: String,
    pub pass: String,
    pub keepalive: bool,
    pub algo: Option<String>,
}

#[derive(Clone)]
struct Job {
    id: String,
    blob: Vec<u8>,
    target: u64,
    seed: Vec<u8>,
}

struct Data {
    seed: Vec<u8>,
    cache: Shared<rx::Cache>,
    dataset: Shared<rx::Dataset>,
}

struct Share {
    job_id: String,
    nonce: u32,
    hash: [u8; 32],
}

pub struct Miner {
    flags: i32,
    threads: usize,
    retries: u32,
    job: Mutex<Option<(u64, Job)>>,
    generation: AtomicU64,
    data: RwLock<Data>,
    pools: Mutex<Vec<Pool>>,
    /// Bumped by a config PUT: the live session drops and logs in again with
    /// the new pools. The dataset stays (it depends on the seed, not the login).
    pools_gen: AtomicU64,
    shares: Mutex<Option<mpsc::Sender<Share>>>,
    next_id: AtomicU64,
    hashes: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    paused: AtomicBool,
    stop: AtomicBool,
    samples: Mutex<VecDeque<(Instant, u64)>>,
    started: Instant,
    http: Mutex<Value>,
    current_pool: Mutex<Option<String>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Pool targets come as 4 bytes (compact) or 8 bytes, little-endian; the
/// hash's last 8 bytes, read the same way, must be below the 64-bit form.
fn parse_target(s: &str) -> Option<u64> {
    let b = unhex(s)?;
    match b.len() {
        4 => {
            let t = u32::from_le_bytes(b.try_into().ok()?) as u64;
            Some(u64::MAX / (0xFFFF_FFFF / t.max(1)))
        }
        8 => Some(u64::from_le_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

fn difficulty(target: u64) -> u64 {
    u64::MAX / target.max(1)
}

fn parse_job(v: &Value) -> Option<Job> {
    let blob = unhex(v["blob"].as_str()?)?;
    if blob.len() < NONCE_AT + 4 {
        return None;
    }
    Some(Job {
        id: v["job_id"].as_str()?.to_string(),
        blob,
        target: parse_target(v["target"].as_str()?)?,
        seed: unhex(v["seed_hash"].as_str()?)?,
    })
}

impl Miner {
    fn new(threads: usize, retries: u32, pools: Vec<Pool>) -> Arc<Self> {
        let base = unsafe { rx::randomx_get_flags() } | rx::FLAG_FULL_MEM;
        // Large pages when the OS grants them, normal pages otherwise.
        let (flags, dataset) = unsafe {
            let d = rx::randomx_alloc_dataset(base | rx::FLAG_LARGE_PAGES);
            if d.is_null() {
                (base, rx::randomx_alloc_dataset(base))
            } else {
                (base | rx::FLAG_LARGE_PAGES, d)
            }
        };
        if dataset.is_null() {
            log("randomx", "failed to allocate RandomX dataset (2080 MB)");
            std::process::exit(1);
        }
        let cache = unsafe {
            let c = rx::randomx_alloc_cache(flags);
            if c.is_null() {
                rx::randomx_alloc_cache(flags & !rx::FLAG_LARGE_PAGES)
            } else {
                c
            }
        };
        if cache.is_null() {
            log("randomx", "failed to allocate RandomX cache (256 MB)");
            std::process::exit(1);
        }
        let lp = flags & rx::FLAG_LARGE_PAGES != 0;
        log(
            "randomx",
            &format!(
                "allocated 2336 MB (2080+256) huge pages {} jit {}",
                if lp { "100%" } else { "0%" },
                if flags & 8 != 0 { "on" } else { "off" }
            ),
        );
        Arc::new(Miner {
            flags,
            threads,
            retries: retries.max(1),
            job: Mutex::new(None),
            generation: AtomicU64::new(0),
            data: RwLock::new(Data { seed: Vec::new(), cache: Shared(cache), dataset: Shared(dataset) }),
            pools: Mutex::new(pools),
            pools_gen: AtomicU64::new(0),
            shares: Mutex::new(None),
            next_id: AtomicU64::new(10),
            hashes: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            samples: Mutex::new(VecDeque::new()),
            started: Instant::now(),
            http: Mutex::new(Value::Null),
            current_pool: Mutex::new(None),
        })
    }

    /// Re-key the dataset for a new seed, in place, across every thread.
    /// Workers hold the read lock per batch, so this waits for the batch in
    /// hand and then has the whole machine.
    fn ensure_seed(&self, seed: &[u8]) {
        if self.data.read().unwrap().seed == seed {
            return;
        }
        let mut d = self.data.write().unwrap();
        if d.seed == seed {
            return;
        }
        let t0 = Instant::now();
        log("randomx", &format!("init dataset algo rx/0 ({} threads) seed {}...", self.threads, &hex(seed)[..16]));
        unsafe { rx::randomx_init_cache(d.cache.0, seed.as_ptr().cast(), seed.len()) };
        let items = unsafe { rx::randomx_dataset_item_count() } as u64;
        let n = self.threads as u64;
        let (cache, ds) = (d.cache, d.dataset);
        std::thread::scope(|s| {
            for i in 0..n {
                let (start, end) = (items * i / n, items * (i + 1) / n);
                s.spawn(move || {
                    let (cache, ds) = (cache, ds);
                    unsafe { rx::randomx_init_dataset(ds.0, cache.0, start as _, (end - start) as _) }
                });
            }
        });
        d.seed = seed.to_vec();
        log("randomx", &format!("dataset ready ({} ms)", t0.elapsed().as_millis()));
    }

    fn set_job(&self, job: Job) {
        let g = self.generation.fetch_add(1, Relaxed) + 1;
        *self.job.lock().unwrap() = Some((g, job));
    }

    fn set_paused(&self, p: bool) {
        if self.paused.swap(p, Relaxed) != p {
            log("cpu", if p { "paused" } else { "resumed" });
        }
    }

    fn worker(self: Arc<Self>, idx: u32) {
        let vm = {
            let d = self.data.read().unwrap();
            unsafe { rx::randomx_create_vm(self.flags, d.cache.0, d.dataset.0) }
        };
        if vm.is_null() {
            log("cpu", &format!("thread #{idx} failed to create a RandomX VM"));
            return;
        }
        let step = self.threads as u32;
        let (mut nonce, mut held) = (idx, 0u64);
        let mut out = [0u8; 32];
        while !self.stop.load(Relaxed) {
            if self.paused.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            let Some((g, job)) = self.job.lock().unwrap().clone() else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            if g != held {
                (held, nonce) = (g, idx);
            }
            let d = self.data.read().unwrap();
            if d.seed != job.seed {
                drop(d);
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            unsafe { rx::randomx_vm_set_dataset(vm, d.dataset.0) };
            let (mut cur, mut next) = (job.blob.clone(), job.blob.clone());
            cur[NONCE_AT..NONCE_AT + 4].copy_from_slice(&nonce.to_le_bytes());
            unsafe { rx::randomx_calculate_hash_first(vm, cur.as_ptr().cast(), cur.len()) };
            for _ in 0..BATCH {
                let n2 = nonce.wrapping_add(step);
                next[NONCE_AT..NONCE_AT + 4].copy_from_slice(&n2.to_le_bytes());
                unsafe {
                    rx::randomx_calculate_hash_next(vm, next.as_ptr().cast(), next.len(), out.as_mut_ptr().cast())
                };
                if u64::from_le_bytes(out[24..32].try_into().unwrap()) < job.target {
                    if let Some(tx) = self.shares.lock().unwrap().as_ref() {
                        let _ = tx.send(Share { job_id: job.id.clone(), nonce, hash: out });
                    }
                }
                nonce = n2;
                std::mem::swap(&mut cur, &mut next);
            }
            // The last hash_first input is discarded: 1 in BATCH, by design.
            drop(d);
            self.hashes.fetch_add(BATCH as u64, Relaxed);
        }
        unsafe { rx::randomx_destroy_vm(vm) };
    }

    /// H/s over the last `secs`, or None until that much history exists
    /// (XMRig reports null for a window it hasn't filled).
    fn rate(&self, secs: u64) -> Option<f64> {
        let s = self.samples.lock().unwrap();
        let (t1, h1) = *s.back()?;
        let want = t1.checked_sub(Duration::from_secs(secs))?;
        let &(t0, h0) = s.iter().find(|(t, _)| *t >= want)?;
        let dt = (t1 - t0).as_secs_f64();
        (dt >= secs as f64 * 0.9).then(|| (h1 - h0) as f64 / dt)
    }

    fn sample(&self) {
        let mut s = self.samples.lock().unwrap();
        s.push_back((Instant::now(), self.hashes.load(Relaxed)));
        while s.len() > 960 {
            s.pop_front();
        }
    }

    pub fn summary(&self) -> Value {
        let good = self.accepted.load(Relaxed);
        let total = good + self.rejected.load(Relaxed);
        let lp = self.flags & rx::FLAG_LARGE_PAGES != 0;
        json!({
            "id": "pasiv-rx",
            "version": VERSION,
            "kind": "cpu",
            "ua": format!("pasiv-rx/{VERSION}"),
            "uptime": self.started.elapsed().as_secs(),
            "paused": self.paused.load(Relaxed),
            "algo": "rx/0",
            "hashrate": {"total": [self.rate(10), self.rate(60), self.rate(900)]},
            "results": {"shares_good": good, "shares_total": total, "hashes_total": self.hashes.load(Relaxed)},
            "connection": {"pool": *self.current_pool.lock().unwrap()},
            "hugepages": if lp { [1168, 1168] } else { [0, 1168] },
            "cpu": {"threads": self.threads},
        })
    }

    pub fn config_json(&self) -> Value {
        let pools: Vec<Value> = self
            .pools
            .lock()
            .unwrap()
            .iter()
            .map(|p| {
                json!({
                    "url": format!("{}:{}", p.endpoint.host, p.endpoint.port),
                    "user": p.user,
                    "pass": p.pass,
                    "keepalive": p.keepalive,
                    "tls": p.endpoint.tls,
                    "tls-fingerprint": p.endpoint.fingerprint,
                    "algo": p.algo,
                })
            })
            .collect();
        json!({
            "autosave": false,
            "watch": false,
            "donate-level": 0,
            "http": *self.http.lock().unwrap(),
            "cpu": {"enabled": true, "max-threads": self.threads},
            "retries": self.retries,
            "pools": pools,
        })
    }

    /// A config PUT: take the new pool list (the fee slice changes `user` on
    /// every pool) and log in again with it. Anything that isn't rx/0 is
    /// refused rather than mined wrongly.
    pub fn apply_config(&self, v: &Value) -> Result<(), String> {
        let arr = v["pools"].as_array().filter(|a| !a.is_empty()).ok_or("config has no pools")?;
        let mut pools = Vec::new();
        for p in arr {
            let url = p["url"].as_str().ok_or("pool without url")?;
            let mut ep = net::parse_endpoint(url).ok_or("bad pool url")?;
            ep.tls |= p["tls"].as_bool().unwrap_or(false);
            ep.fingerprint = p["tls-fingerprint"].as_str().map(str::to_string);
            let algo = p["algo"].as_str().map(str::to_string);
            if algo.as_deref().is_some_and(|a| a != "rx/0") {
                return Err(format!("unsupported algo {}", algo.unwrap()));
            }
            pools.push(Pool {
                endpoint: ep,
                user: p["user"].as_str().ok_or("pool without user")?.to_string(),
                pass: p["pass"].as_str().unwrap_or("x").to_string(),
                keepalive: p["keepalive"].as_bool().unwrap_or(false),
                algo,
            });
        }
        *self.pools.lock().unwrap() = pools;
        self.pools_gen.fetch_add(1, Relaxed);
        log("config", "pools updated");
        Ok(())
    }

    /// Pool loop with XMRig's failover: `retries` attempts on a pool, then the
    /// next; from a backup it returns to the primary as soon as the primary
    /// accepts a connection again.
    fn pool_loop(self: Arc<Self>) {
        let (mut idx, mut failures) = (0usize, 0u32);
        while !self.stop.load(Relaxed) {
            let pools = self.pools.lock().unwrap().clone();
            let pool = pools[idx % pools.len()].clone();
            let label = format!("{}:{}", pool.endpoint.host, pool.endpoint.port);
            let gen = self.pools_gen.load(Relaxed);
            let primary = (idx % pools.len() != 0).then(|| pools[0].endpoint.clone());
            let r = self.session(&pool, &label, gen, primary);
            *self.shares.lock().unwrap() = None;
            *self.current_pool.lock().unwrap() = None;
            match r {
                Ok(Next::Primary) | Ok(Next::Reload) => {
                    (idx, failures) = (0, 0);
                    continue;
                }
                Ok(Next::Stop) => break,
                Err(e) => {
                    log("net", &format!("{label} {e}"));
                    failures += 1;
                    if failures >= self.retries {
                        (idx, failures) = (idx + 1, 0);
                        if idx % pools.len() == 0 {
                            log("net", "no active pools, stop mining");
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    fn session(&self, pool: &Pool, label: &str, gen: u64, primary: Option<net::Endpoint>) -> Result<Next, String> {
        let mut conn = net::Conn::connect(&pool.endpoint).map_err(|e| format!("connect error: \"{e}\""))?;
        log("net", &format!("use pool {label}{}", if pool.endpoint.tls { " TLS" } else { "" }));
        *self.current_pool.lock().unwrap() = Some(label.to_string());
        let (tx, rx) = mpsc::channel::<Share>();
        let mut session = String::new();
        conn.send_line(
            &json!({
                "id": 1, "jsonrpc": "2.0", "method": "login",
                "params": {"login": pool.user, "pass": pool.pass, "agent": format!("pasiv-rx/{VERSION}"), "algo": ["rx/0"]}
            })
            .to_string(),
        )
        .map_err(|e| format!("write error: \"{e}\""))?;
        let (mut last_ping, mut last_heard, mut last_probe) = (Instant::now(), Instant::now(), Instant::now());
        let mut diffs: std::collections::HashMap<u64, u64> = Default::default();
        let mut current_diff = 0u64;
        loop {
            if self.stop.load(Relaxed) {
                return Ok(Next::Stop);
            }
            if self.pools_gen.load(Relaxed) != gen {
                return Ok(Next::Reload);
            }
            if let Some(p) = &primary {
                if last_probe.elapsed() > Duration::from_secs(60) {
                    last_probe = Instant::now();
                    if std::net::TcpStream::connect_timeout(
                        &match std::net::ToSocketAddrs::to_socket_addrs(&(p.host.as_str(), p.port)).ok().and_then(|mut a| a.next()) {
                            Some(a) => a,
                            None => continue,
                        },
                        Duration::from_secs(5),
                    )
                    .is_ok()
                    {
                        log("net", &format!("{}:{} is back, returning to the primary pool", p.host, p.port));
                        return Ok(Next::Primary);
                    }
                }
            }
            while let Ok(s) = rx.try_recv() {
                let id = self.next_id.fetch_add(1, Relaxed);
                diffs.insert(id, current_diff);
                conn.send_line(
                    &json!({
                        "id": id, "jsonrpc": "2.0", "method": "submit",
                        "params": {"id": session, "job_id": s.job_id, "nonce": hex(&s.nonce.to_le_bytes()), "result": hex(&s.hash)}
                    })
                    .to_string(),
                )
                .map_err(|e| format!("write error: \"{e}\""))?;
            }
            if pool.keepalive && !session.is_empty() && last_ping.elapsed() > Duration::from_secs(60) {
                let id = self.next_id.fetch_add(1, Relaxed);
                conn.send_line(&json!({"id": id, "jsonrpc": "2.0", "method": "keepalived", "params": {"id": session}}).to_string())
                    .map_err(|e| format!("write error: \"{e}\""))?;
                last_ping = Instant::now();
            }
            if last_heard.elapsed() > Duration::from_secs(if pool.keepalive { 180 } else { 600 }) {
                return Err("read error: \"connection timed out\"".into());
            }
            let line = match conn.read_line() {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(e) if e.contains("closed") => return Err("read error: \"end of file\"".into()),
                Err(e) => return Err(format!("read error: \"{e}\"")),
            };
            last_heard = Instant::now();
            let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
            if msg["method"] == "job" {
                current_diff = self.on_job(&msg["params"], label).unwrap_or(current_diff);
            } else if msg["id"] == 1 {
                if !msg["error"].is_null() {
                    return Err(format!(
                        "login error code: {}, message: \"{}\"",
                        msg["error"]["code"],
                        msg["error"]["message"].as_str().unwrap_or("refused")
                    ));
                }
                let r = &msg["result"];
                session = r["id"].as_str().unwrap_or_default().to_string();
                *self.shares.lock().unwrap() = Some(tx.clone());
                current_diff = self.on_job(&r["job"], label).unwrap_or(0);
            } else if let Some(id) = msg["id"].as_u64().filter(|i| *i >= 10) {
                let diff = diffs.remove(&id).unwrap_or(0);
                if msg["error"].is_null() {
                    let a = self.accepted.fetch_add(1, Relaxed) + 1;
                    log("cpu", &format!("accepted ({a}/{}) diff {diff}", self.rejected.load(Relaxed)));
                } else {
                    let r = self.rejected.fetch_add(1, Relaxed) + 1;
                    log(
                        "cpu",
                        &format!(
                            "rejected ({}/{r}) diff {diff} \"{}\"",
                            self.accepted.load(Relaxed),
                            msg["error"]["message"].as_str().unwrap_or("rejected")
                        ),
                    );
                }
            }
        }
    }

    fn on_job(&self, v: &Value, label: &str) -> Option<u64> {
        let Some(job) = parse_job(v) else {
            log("net", &format!("{label} received an unparseable job"));
            return None;
        };
        let diff = difficulty(job.target);
        log(
            "net",
            &format!("new job from {label} diff {diff} algo rx/0 height {}", v["height"].as_u64().unwrap_or(0)),
        );
        self.ensure_seed(&job.seed);
        self.set_job(job);
        Some(diff)
    }
}

enum Next {
    Primary,
    Reload,
    Stop,
}

/// XMRig's command line, the parts Pasiv uses. `-u/-p/-k/--tls/-a` apply to
/// the most recent `-o`, exactly as XMRig scopes them.
struct Args {
    config: Option<String>,
    pools: Vec<Pool>,
    threads: Option<usize>,
    retries: u32,
    bench: bool,
    seconds: Option<u64>,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { config: None, pools: Vec::new(), threads: None, retries: 5, bench: false, seconds: None };
    let mut i = 1;
    let val = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        argv.get(*i).cloned().ok_or_else(|| format!("{} needs a value", argv[*i - 1]))
    };
    while i < argv.len() {
        let flag = argv[i].as_str();
        let (flag, inline) = match flag.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (flag, None),
        };
        let take = |i: &mut usize| -> Result<String, String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => val(i),
            }
        };
        let last = a.pools.last_mut();
        match flag {
            "-c" | "--config" => a.config = Some(take(&mut i)?),
            "-o" | "--url" => {
                let url = take(&mut i)?;
                let endpoint = net::parse_endpoint(&url).ok_or_else(|| format!("bad pool url {url}"))?;
                a.pools.push(Pool { endpoint, user: "x".into(), pass: "x".into(), keepalive: false, algo: None });
            }
            "-u" | "--user" => last.ok_or("-u before -o")?.user = take(&mut i)?,
            "-p" | "--pass" => last.ok_or("-p before -o")?.pass = take(&mut i)?,
            "-k" | "--keepalive" => last.ok_or("-k before -o")?.keepalive = true,
            "--tls" => last.ok_or("--tls before -o")?.endpoint.tls = true,
            "--tls-fingerprint" => last.ok_or("--tls-fingerprint before -o")?.endpoint.fingerprint = Some(take(&mut i)?),
            "-a" | "--algo" => {
                let algo = take(&mut i)?;
                if algo != "rx/0" {
                    return Err(format!("unsupported algo {algo} (pasiv-rx mines rx/0 only)"));
                }
                last.ok_or("-a before -o")?.algo = Some(algo);
            }
            "-t" | "--threads" => a.threads = Some(take(&mut i)?.parse().map_err(|_| "bad -t")?),
            "--retries" => a.retries = take(&mut i)?.parse().map_err(|_| "bad --retries")?,
            "--seconds" => a.seconds = Some(take(&mut i)?.parse().map_err(|_| "bad --seconds")?),
            "--bench" => a.bench = true,
            // Accepted and meaningless here: there is no donation, no colour.
            "--donate-level" | "--retry-pause" | "--rig-id" | "--cpu-priority" => {
                take(&mut i)?;
            }
            "--no-color" | "--nicehash" => {}
            "-V" | "--version" => {
                println!("pasiv-rx {VERSION}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other}")),
        }
        i += 1;
    }
    Ok(a)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pasiv-rx: {e}");
            std::process::exit(2);
        }
    };
    log("info", &format!("pasiv-rx {VERSION} (RandomX 1.2.1)"));
    let http = args.config.as_ref().map(|p| {
        let text = std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("pasiv-rx: config {p}: {e}");
            std::process::exit(2);
        });
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
            eprintln!("pasiv-rx: config {p}: {e}");
            std::process::exit(2);
        });
        v["http"].clone()
    });
    if !args.bench && args.pools.is_empty() {
        eprintln!("pasiv-rx: no pools (-o host:port -u LOGIN)");
        std::process::exit(2);
    }
    let threads = args
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1);
    let m = Miner::new(threads, args.retries, args.pools.clone());

    if let Some(h) = http.filter(|h| h["enabled"].as_bool() == Some(true)) {
        let host = h["host"].as_str().unwrap_or("127.0.0.1").to_string();
        let port = h["port"].as_u64().unwrap_or(0) as u16;
        let token = h["access-token"].as_str().map(str::to_string);
        // Echo the http block without the token, as the config document.
        let mut shown = h.clone();
        shown["access-token"] = Value::Null;
        *m.http.lock().unwrap() = shown;
        if host != "127.0.0.1" && host != "::1" && host != "localhost" {
            eprintln!("pasiv-rx: the API binds to loopback only");
            std::process::exit(2);
        }
        let ma = m.clone();
        std::thread::spawn(move || api::serve(ma, &host, port, token));
    }

    if args.bench {
        let seed = vec![0u8; 32];
        m.ensure_seed(&seed);
        m.set_job(Job { id: "bench".into(), blob: vec![7u8; 76], target: 0, seed });
    } else {
        let mp = m.clone();
        std::thread::spawn(move || mp.pool_loop());
    }
    let workers: Vec<_> = (0..threads as u32)
        .map(|i| {
            let mw = m.clone();
            std::thread::spawn(move || mw.worker(i))
        })
        .collect();
    log("cpu", &format!("READY threads {threads}/{threads}"));

    let start = Instant::now();
    let mut tick = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        m.sample();
        tick += 1;
        if tick % 60 == 0 {
            let f = |r: Option<f64>| r.map_or("n/a".to_string(), |v| format!("{v:.1}"));
            log(
                "miner",
                &format!("speed 10s/60s/15m {} {} {} H/s", f(m.rate(10)), f(m.rate(60)), f(m.rate(900))),
            );
        }
        if args.seconds.is_some_and(|s| start.elapsed().as_secs() >= s) {
            let r = m.rate(args.seconds.unwrap().saturating_sub(15).max(10));
            log("miner", &format!("average {:.1} H/s", r.unwrap_or(0.0)));
            m.stop.store(true, Relaxed);
            break;
        }
    }
    for w in workers {
        let _ = w.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        std::iter::once("pasiv-rx").chain(s.split_whitespace()).map(String::from).collect()
    }

    #[test]
    fn parses_pasivs_xmrig_command_line() {
        // Exactly the shape miners::xmrig::build_args produces.
        let a = parse_args(&argv(
            "-c C:\\x\\xmrig-runtime.json -o rx.unmineable.com:3333 -u BTC:abc.w -p pasiv -k -a rx/0 \
             -o rx.unmineable.com:443 -u BTC:abc.w -p pasiv -k --tls -a rx/0 \
             -t 11 --retries 1 --no-color --donate-level 1",
        ))
        .unwrap();
        assert_eq!(a.config.as_deref(), Some("C:\\x\\xmrig-runtime.json"));
        assert_eq!(a.pools.len(), 2);
        assert_eq!(a.pools[0].endpoint.port, 3333);
        assert!(!a.pools[0].endpoint.tls);
        assert!(a.pools[1].endpoint.tls && a.pools[1].keepalive);
        assert_eq!(a.pools[1].user, "BTC:abc.w");
        assert_eq!(a.pools[0].pass, "pasiv");
        assert_eq!((a.threads, a.retries), (Some(11), 1));
    }

    #[test]
    fn refuses_other_algorithms_and_unknown_flags() {
        assert!(parse_args(&argv("-o h:1 -u x -a rx/wow")).is_err());
        assert!(parse_args(&argv("-o h:1 --bogus")).is_err());
        assert!(parse_args(&argv("-u x")).is_err());
    }

    #[test]
    fn compact_and_full_targets() {
        // XMRig: 0xFFFFFFFFFFFFFFFF / (0xFFFFFFFF / t32)
        assert_eq!(parse_target("b88d0600"), Some(u64::MAX / (0xFFFF_FFFF / 0x00068db8)));
        assert_eq!(parse_target("0100000000000000"), Some(1));
        assert_eq!(parse_target("zz"), None);
    }
}
